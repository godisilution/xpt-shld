import { supabase } from './supabase'
import type {
  IncidentLog,
  BlockedIP,
  AIReport,
  IncidentStats,
  IncidentFilters,
  PaginationOptions,
  PaginatedResult,
  DateRange,
  ThreatCategory,
} from './core/types'

export const shieldClient = {
  // ──── Incidents ──────────────────────────────────────────

  async logIncident(incident: IncidentLog): Promise<void> {
    const { error } = await supabase.from('shield_incidents').insert({
      timestamp: incident.timestamp,
      source_ip: incident.sourceIP,
      request_path: incident.requestPath,
      request_method: incident.requestMethod,
      attack_category: incident.attackCategory,
      matched_payload: incident.matchedPayload.substring(0, 500),
      confidence: incident.confidence,
      raw_input: incident.rawInput.substring(0, 1000),
      action: incident.action,
      user_agent: incident.userAgent.substring(0, 500),
      geo_location: incident.geoLocation || null,
    })
    if (error) {
      console.error('[xpecto-shield] Failed to log incident:', error)
      throw error
    }
  },

  async getIncidents(
    options: PaginationOptions & { filters?: IncidentFilters }
  ): Promise<PaginatedResult<IncidentLog>> {
    const page = options.page || 1
    const limit = options.limit || 25
    const from = (page - 1) * limit
    const to = from + limit - 1

    let query = supabase
      .from('shield_incidents')
      .select('*', { count: 'exact' })

    if (options.filters?.category) {
      query = query.eq('attack_category', options.filters.category)
    }
    if (options.filters?.sourceIP) {
      query = query.eq('source_ip', options.filters.sourceIP)
    }
    if (options.filters?.action) {
      query = query.eq('action', options.filters.action)
    }
    if (options.filters?.dateFrom) {
      query = query.gte('timestamp', options.filters.dateFrom)
    }
    if (options.filters?.dateTo) {
      query = query.lte('timestamp', options.filters.dateTo)
    }
    if (options.filters?.minConfidence !== undefined) {
      query = query.gte('confidence', options.filters.minConfidence)
    }

    const sortBy = options.sortBy === 'timestamp' ? 'timestamp' : 'created_at'
    const ascending = options.sortOrder === 'asc'

    query = query.order(sortBy, { ascending }).range(from, to)

    const { data, count, error } = await query
    if (error) throw error

    return {
      data: (data || []).map(mapIncidentRow),
      total: count || 0,
      page,
      limit,
      hasMore: page * limit < (count || 0),
    }
  },

  async getIncidentStats(dateRange?: DateRange): Promise<IncidentStats> {
    let query = supabase
      .from('shield_incidents')
      .select('*')
      .limit(5000)

    if (dateRange) {
      query = query.gte('timestamp', dateRange.start).lte('timestamp', dateRange.end)
    }

    const { data: incidents, error } = await query
    if (error) throw error

    const docs = incidents || []

    const categoryBreakdown: Record<ThreatCategory, number> = {
      sqli: 0, xss: 0, lfi: 0, ssrf: 0, 'path-traversal': 0,
    }
    const ipCounts: Record<string, { count: number; lastCategory: ThreatCategory }> = {}
    const hourCounts: Record<string, number> = {}
    let totalConfidence = 0

    for (const doc of docs) {
      const cat = doc.attack_category as ThreatCategory
      categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1

      const ip = doc.source_ip as string
      if (!ipCounts[ip]) ipCounts[ip] = { count: 0, lastCategory: cat }
      ipCounts[ip].count++
      ipCounts[ip].lastCategory = cat

      const hour = (doc.timestamp as string).substring(0, 13)
      hourCounts[hour] = (hourCounts[hour] || 0) + 1

      totalConfidence += doc.confidence as number
    }

    let totalBlockedIPs = 0
    try {
      const { count } = await supabase
        .from('shield_blocked_ips')
        .select('*', { count: 'exact', head: true })
        .eq('is_active', true)
      totalBlockedIPs = count || 0
    } catch { /* ignore */ }

    const topAttackerIPs = Object.entries(ipCounts)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10)
      .map(([ip, data]) => ({ ip, count: data.count, lastCategory: data.lastCategory }))

    const hourlyTimeline = Object.entries(hourCounts)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(-24)
      .map(([hour, count]) => ({ hour, count }))

    return {
      totalIncidents: docs.length,
      totalBlockedIPs,
      activeThreats: docs.filter((doc) => {
        const ts = new Date(doc.timestamp as string).getTime()
        return Date.now() - ts < 3600_000
      }).length,
      categoryBreakdown,
      hourlyTimeline,
      topAttackerIPs,
      averageConfidence: docs.length > 0 ? totalConfidence / docs.length : 0,
    }
  },

  // ──── Blocked IPs ────────────────────────────────────────

  async isIPBlocked(ip: string): Promise<boolean> {
    try {
      const { data } = await supabase
        .from('shield_blocked_ips')
        .select('*')
        .eq('ip_address', ip)
        .eq('is_active', true)
        .limit(1)
        .maybeSingle()

      if (!data) return false

      if (data.expires_at && new Date(data.expires_at).getTime() < Date.now()) {
        await supabase
          .from('shield_blocked_ips')
          .update({ is_active: false })
          .eq('id', data.id)
        return false
      }

      return true
    } catch {
      return false
    }
  },

  async getIPRecord(ip: string): Promise<BlockedIP | null> {
    const { data } = await supabase
      .from('shield_blocked_ips')
      .select('*')
      .eq('ip_address', ip)
      .limit(1)
      .maybeSingle()

    if (!data) return null
    return mapBlockedIPRow(data)
  },

  async incrementStrike(ip: string, category: ThreatCategory): Promise<number> {
    const existing = await shieldClient.getIPRecord(ip)

    if (existing) {
      const newCount = existing.strikeCount + 1
      await supabase
        .from('shield_blocked_ips')
        .update({ strike_count: newCount, last_attack_category: category })
        .eq('id', existing.id)
      return newCount
    }

    await supabase.from('shield_blocked_ips').insert({
      ip_address: ip,
      reason: 'auto',
      strike_count: 1,
      blocked_at: new Date().toISOString(),
      expires_at: null,
      last_attack_category: category,
      is_active: false,
    })
    return 1
  },

  async blockIP(ip: string, reason: 'auto' | 'manual', duration?: number): Promise<void> {
    const expiresAt = duration
      ? new Date(Date.now() + duration * 1000).toISOString()
      : null

    const existing = await shieldClient.getIPRecord(ip)

    if (existing) {
      await supabase
        .from('shield_blocked_ips')
        .update({
          reason,
          blocked_at: new Date().toISOString(),
          expires_at: expiresAt,
          is_active: true,
        })
        .eq('id', existing.id)
    } else {
      await supabase.from('shield_blocked_ips').insert({
        ip_address: ip,
        reason,
        strike_count: 0,
        blocked_at: new Date().toISOString(),
        expires_at: expiresAt,
        last_attack_category: 'sqli',
        is_active: true,
      })
    }
  },

  async unblockIP(ip: string): Promise<void> {
    await supabase
      .from('shield_blocked_ips')
      .update({ is_active: false })
      .eq('ip_address', ip)
  },

  async getBlockedIPs(options: PaginationOptions): Promise<PaginatedResult<BlockedIP>> {
    const page = options.page || 1
    const limit = options.limit || 25
    const from = (page - 1) * limit
    const to = from + limit - 1

    const { data, count, error } = await supabase
      .from('shield_blocked_ips')
      .select('*', { count: 'exact' })
      .eq('is_active', true)
      .order('created_at', { ascending: false })
      .range(from, to)

    if (error) throw error

    return {
      data: (data || []).map(mapBlockedIPRow),
      total: count || 0,
      page,
      limit,
      hasMore: page * limit < (count || 0),
    }
  },

  // ──── AI Reports ─────────────────────────────────────────

  async saveReport(report: AIReport): Promise<string> {
    const { data, error } = await supabase
      .from('shield_ai_reports')
      .insert({
        date_range_start: report.dateRangeStart,
        date_range_end: report.dateRangeEnd,
        incident_count: report.incidentCount,
        executive_summary: report.executiveSummary,
        pattern_analysis: report.patternAnalysis,
        trend_analysis: report.trendAnalysis,
        risk_assessment: report.riskAssessment,
        recommendations: report.recommendations,
        threat_level: report.threatLevel,
        model_used: report.modelUsed,
      })
      .select('id')
      .single()

    if (error) throw error
    return data.id
  },

  async getReport(id: string): Promise<AIReport> {
    const { data, error } = await supabase
      .from('shield_ai_reports')
      .select('*')
      .eq('id', id)
      .single()

    if (error) throw error
    return mapReportRow(data)
  },

  async getReports(options: PaginationOptions): Promise<PaginatedResult<AIReport>> {
    const page = options.page || 1
    const limit = options.limit || 10
    const from = (page - 1) * limit
    const to = from + limit - 1

    const { data, count, error } = await supabase
      .from('shield_ai_reports')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to)

    if (error) throw error

    return {
      data: (data || []).map(mapReportRow),
      total: count || 0,
      page,
      limit,
      hasMore: page * limit < (count || 0),
    }
  },

  // ──── Settings ───────────────────────────────────────────

  async getSetting(key: string): Promise<string | null> {
    const { data } = await supabase
      .from('shield_settings')
      .select('value')
      .eq('key', key)
      .maybeSingle()

    return data?.value ?? null
  },

  async setSetting(key: string, value: string): Promise<void> {
    const { data: existing } = await supabase
      .from('shield_settings')
      .select('id')
      .eq('key', key)
      .maybeSingle()

    if (existing) {
      await supabase
        .from('shield_settings')
        .update({ value })
        .eq('key', key)
    } else {
      await supabase.from('shield_settings').insert({ key, value })
    }
  },

  async getAllSettings(): Promise<Record<string, string>> {
    const { data } = await supabase
      .from('shield_settings')
      .select('key, value')
      .limit(100)

    const settings: Record<string, string> = {}
    for (const row of data || []) {
      settings[row.key] = row.value
    }
    return settings
  },
}

// ──── Row Mapping Helpers ────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapIncidentRow(row: any): IncidentLog {
  return {
    id: row.id,
    timestamp: row.timestamp,
    sourceIP: row.source_ip,
    requestPath: row.request_path,
    requestMethod: row.request_method,
    attackCategory: row.attack_category,
    matchedPayload: row.matched_payload,
    confidence: row.confidence,
    rawInput: row.raw_input,
    action: row.action,
    userAgent: row.user_agent,
    geoLocation: row.geo_location,
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapBlockedIPRow(row: any): BlockedIP {
  return {
    id: row.id,
    ipAddress: row.ip_address,
    reason: row.reason,
    strikeCount: row.strike_count,
    blockedAt: row.blocked_at,
    expiresAt: row.expires_at,
    lastAttackCategory: row.last_attack_category,
    isActive: row.is_active,
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapReportRow(row: any): AIReport {
  return {
    id: row.id,
    createdAt: row.created_at,
    dateRangeStart: row.date_range_start,
    dateRangeEnd: row.date_range_end,
    incidentCount: row.incident_count,
    executiveSummary: row.executive_summary,
    patternAnalysis: row.pattern_analysis,
    trendAnalysis: row.trend_analysis,
    riskAssessment: row.risk_assessment,
    recommendations: row.recommendations,
    threatLevel: row.threat_level,
    modelUsed: row.model_used,
  }
}
