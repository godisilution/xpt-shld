// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Appwrite Client Wrapper
// ═══════════════════════════════════════════════════════════════
//
// Wraps the Appwrite SDK to provide typed CRUD operations
// for incidents, blocked IPs, AI reports, and settings.
// Auto-creates required collections on first use.
// ═══════════════════════════════════════════════════════════════

import { Client, Databases, Query, ID, Permission, Role } from 'node-appwrite'
import type {
  AppwriteConfig,
  ShieldAppwriteClient,
  IncidentLog,
  BlockedIP,
  AIReport,
  IncidentStats,
  IncidentFilters,
  PaginationOptions,
  PaginatedResult,
  DateRange,
  ThreatCategory,
} from '../core/types'
import { THREAT_CATEGORIES } from '../core/types'

// ─── Collection IDs ────────────────────────────────────────────

const COLLECTIONS = {
  INCIDENTS: 'shield_incidents',
  BLOCKED_IPS: 'shield_blocked_ips',
  AI_REPORTS: 'shield_ai_reports',
  SETTINGS: 'shield_settings',
} as const

// ─── Factory ───────────────────────────────────────────────────

/**
 * Create an Appwrite client wrapper for Xpecto Shield.
 *
 * @param config - Appwrite connection configuration
 * @returns A fully typed ShieldAppwriteClient
 */
export function createAppwriteClient(
  config: AppwriteConfig
): ShieldAppwriteClient {
  const {
    endpoint,
    projectId,
    apiKey,
    databaseId = 'xpecto_shield',
  } = config

  // Initialize Appwrite SDK
  const client = new Client()
    .setEndpoint(endpoint)
    .setProject(projectId)
    .setKey(apiKey)

  const databases = new Databases(client)

  // ─── Helpers ─────────────────────────────────────────────

  async function documentExists(
    collectionId: string,
    documentId: string
  ): Promise<boolean> {
    try {
      await databases.getDocument(databaseId, collectionId, documentId)
      return true
    } catch {
      return false
    }
  }

  function buildPaginationQueries(options: PaginationOptions): string[] {
    const queries: string[] = []
    const limit = options.limit || 25
    const page = options.page || 1
    const offset = (page - 1) * limit

    queries.push(Query.limit(limit))
    queries.push(Query.offset(offset))

    if (options.sortBy) {
      queries.push(
        options.sortOrder === 'asc'
          ? Query.orderAsc(options.sortBy)
          : Query.orderDesc(options.sortBy)
      )
    } else {
      queries.push(Query.orderDesc('$createdAt'))
    }

    return queries
  }

  function buildIncidentFilterQueries(filters: IncidentFilters): string[] {
    const queries: string[] = []

    if (filters.category) {
      queries.push(Query.equal('attackCategory', filters.category))
    }
    if (filters.sourceIP) {
      queries.push(Query.equal('sourceIP', filters.sourceIP))
    }
    if (filters.action) {
      queries.push(Query.equal('action', filters.action))
    }
    if (filters.dateFrom) {
      queries.push(Query.greaterThanEqual('timestamp', filters.dateFrom))
    }
    if (filters.dateTo) {
      queries.push(Query.lessThanEqual('timestamp', filters.dateTo))
    }
    if (filters.minConfidence !== undefined) {
      queries.push(Query.greaterThanEqual('confidence', filters.minConfidence))
    }

    return queries
  }

  // ─── Client Implementation ──────────────────────────────

  const shieldClient: ShieldAppwriteClient = {
    // ════════════════ Incidents ════════════════════════════

    async logIncident(incident: IncidentLog): Promise<void> {
      try {
        await databases.createDocument(
          databaseId,
          COLLECTIONS.INCIDENTS,
          ID.unique(),
          {
            timestamp: incident.timestamp,
            sourceIP: incident.sourceIP,
            requestPath: incident.requestPath,
            requestMethod: incident.requestMethod,
            attackCategory: incident.attackCategory,
            matchedPayload: incident.matchedPayload.substring(0, 500),
            confidence: incident.confidence,
            rawInput: incident.rawInput.substring(0, 1000),
            action: incident.action,
            userAgent: incident.userAgent.substring(0, 500),
            geoLocation: incident.geoLocation || null,
          }
        )
      } catch (error) {
        console.error('[xpecto-shield] Failed to log incident:', error)
        throw error
      }
    },

    async getIncidents(
      options: PaginationOptions & { filters?: IncidentFilters }
    ): Promise<PaginatedResult<IncidentLog>> {
      const queries = [
        ...buildPaginationQueries(options),
        ...(options.filters ? buildIncidentFilterQueries(options.filters) : []),
      ]

      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.INCIDENTS,
        queries
      )

      const limit = options.limit || 25
      const page = options.page || 1

      return {
        data: response.documents.map((doc) => ({
          id: doc.$id,
          timestamp: doc.timestamp as string,
          sourceIP: doc.sourceIP as string,
          requestPath: doc.requestPath as string,
          requestMethod: doc.requestMethod as string,
          attackCategory: doc.attackCategory as ThreatCategory,
          matchedPayload: doc.matchedPayload as string,
          confidence: doc.confidence as number,
          rawInput: doc.rawInput as string,
          action: doc.action as 'blocked' | 'logged',
          userAgent: doc.userAgent as string,
          geoLocation: doc.geoLocation as string | undefined,
        })),
        total: response.total,
        page,
        limit,
        hasMore: page * limit < response.total,
      }
    },

    async getIncidentStats(dateRange?: DateRange): Promise<IncidentStats> {
      const queries: string[] = [Query.limit(5000)]

      if (dateRange) {
        queries.push(Query.greaterThanEqual('timestamp', dateRange.start))
        queries.push(Query.lessThanEqual('timestamp', dateRange.end))
      }

      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.INCIDENTS,
        queries
      )

      const categoryBreakdown: Record<ThreatCategory, number> = {
        sqli: 0, xss: 0, lfi: 0, ssrf: 0, 'path-traversal': 0,
      }

      const ipCounts: Record<string, { count: number; lastCategory: ThreatCategory }> = {}
      const hourCounts: Record<string, number> = {}
      let totalConfidence = 0

      for (const doc of response.documents) {
        const cat = doc.attackCategory as ThreatCategory
        categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1

        const ip = doc.sourceIP as string
        if (!ipCounts[ip]) ipCounts[ip] = { count: 0, lastCategory: cat }
        ipCounts[ip].count++
        ipCounts[ip].lastCategory = cat

        const hour = (doc.timestamp as string).substring(0, 13)
        hourCounts[hour] = (hourCounts[hour] || 0) + 1

        totalConfidence += doc.confidence as number
      }

      // Count blocked IPs
      let totalBlockedIPs = 0
      try {
        const blocked = await databases.listDocuments(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          [Query.equal('isActive', true), Query.limit(1)]
        )
        totalBlockedIPs = blocked.total
      } catch { /* ignore */ }

      // Build top attacker IPs
      const topAttackerIPs = Object.entries(ipCounts)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 10)
        .map(([ip, data]) => ({
          ip,
          count: data.count,
          lastCategory: data.lastCategory,
        }))

      // Build hourly timeline
      const hourlyTimeline = Object.entries(hourCounts)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .slice(-24)
        .map(([hour, count]) => ({ hour, count }))

      return {
        totalIncidents: response.total,
        totalBlockedIPs,
        activeThreats: response.documents.filter(
          (doc) => {
            const ts = new Date(doc.timestamp as string).getTime()
            return Date.now() - ts < 3600_000 // Last hour
          }
        ).length,
        categoryBreakdown,
        hourlyTimeline,
        topAttackerIPs,
        averageConfidence: response.total > 0
          ? totalConfidence / response.total
          : 0,
      }
    },

    // ════════════════ Blocked IPs ══════════════════════════

    async isIPBlocked(ip: string): Promise<boolean> {
      try {
        const response = await databases.listDocuments(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          [
            Query.equal('ipAddress', ip),
            Query.equal('isActive', true),
            Query.limit(1),
          ]
        )

        if (response.documents.length === 0) return false

        const doc = response.documents[0]
        const expiresAt = doc.expiresAt as string | null

        if (expiresAt && new Date(expiresAt).getTime() < Date.now()) {
          // Block has expired — deactivate
          await databases.updateDocument(
            databaseId,
            COLLECTIONS.BLOCKED_IPS,
            doc.$id,
            { isActive: false }
          )
          return false
        }

        return true
      } catch {
        return false
      }
    },

    async getIPRecord(ip: string): Promise<BlockedIP | null> {
      try {
        const response = await databases.listDocuments(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          [Query.equal('ipAddress', ip), Query.limit(1)]
        )

        if (response.documents.length === 0) return null

        const doc = response.documents[0]
        return {
          id: doc.$id,
          ipAddress: doc.ipAddress as string,
          reason: doc.reason as 'auto' | 'manual',
          strikeCount: doc.strikeCount as number,
          blockedAt: doc.blockedAt as string,
          expiresAt: doc.expiresAt as string | null,
          lastAttackCategory: doc.lastAttackCategory as ThreatCategory,
          isActive: doc.isActive as boolean,
        }
      } catch {
        return null
      }
    },

    async incrementStrike(ip: string, category: ThreatCategory): Promise<number> {
      const existing = await shieldClient.getIPRecord(ip)

      if (existing) {
        const newCount = existing.strikeCount + 1
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          existing.id!,
          {
            strikeCount: newCount,
            lastAttackCategory: category,
          }
        )
        return newCount
      }

      // Create new record
      await databases.createDocument(
        databaseId,
        COLLECTIONS.BLOCKED_IPS,
        ID.unique(),
        {
          ipAddress: ip,
          reason: 'auto',
          strikeCount: 1,
          blockedAt: new Date().toISOString(),
          expiresAt: null,
          lastAttackCategory: category,
          isActive: false,
        }
      )
      return 1
    },

    async blockIP(
      ip: string,
      reason: 'auto' | 'manual',
      duration?: number
    ): Promise<void> {
      const expiresAt = duration
        ? new Date(Date.now() + duration * 1000).toISOString()
        : null

      const existing = await shieldClient.getIPRecord(ip)

      if (existing) {
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          existing.id!,
          {
            reason,
            blockedAt: new Date().toISOString(),
            expiresAt,
            isActive: true,
          }
        )
      } else {
        await databases.createDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          ID.unique(),
          {
            ipAddress: ip,
            reason,
            strikeCount: 0,
            blockedAt: new Date().toISOString(),
            expiresAt,
            lastAttackCategory: 'sqli',
            isActive: true,
          }
        )
      }
    },

    async unblockIP(ip: string): Promise<void> {
      const existing = await shieldClient.getIPRecord(ip)
      if (existing) {
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          existing.id!,
          { isActive: false }
        )
      }
    },

    async getBlockedIPs(
      options: PaginationOptions
    ): Promise<PaginatedResult<BlockedIP>> {
      const queries = [
        ...buildPaginationQueries(options),
        Query.equal('isActive', true),
      ]

      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.BLOCKED_IPS,
        queries
      )

      const limit = options.limit || 25
      const page = options.page || 1

      return {
        data: response.documents.map((doc) => ({
          id: doc.$id,
          ipAddress: doc.ipAddress as string,
          reason: doc.reason as 'auto' | 'manual',
          strikeCount: doc.strikeCount as number,
          blockedAt: doc.blockedAt as string,
          expiresAt: doc.expiresAt as string | null,
          lastAttackCategory: doc.lastAttackCategory as ThreatCategory,
          isActive: doc.isActive as boolean,
        })),
        total: response.total,
        page,
        limit,
        hasMore: page * limit < response.total,
      }
    },

    // ════════════════ AI Reports ═══════════════════════════

    async saveReport(report: AIReport): Promise<string> {
      const doc = await databases.createDocument(
        databaseId,
        COLLECTIONS.AI_REPORTS,
        ID.unique(),
        {
          createdAt: report.createdAt,
          dateRangeStart: report.dateRangeStart,
          dateRangeEnd: report.dateRangeEnd,
          incidentCount: report.incidentCount,
          executiveSummary: report.executiveSummary,
          patternAnalysis: report.patternAnalysis,
          trendAnalysis: report.trendAnalysis,
          riskAssessment: report.riskAssessment,
          recommendations: report.recommendations,
          threatLevel: report.threatLevel,
          modelUsed: report.modelUsed,
        }
      )
      return doc.$id
    },

    async getReport(id: string): Promise<AIReport> {
      const doc = await databases.getDocument(
        databaseId,
        COLLECTIONS.AI_REPORTS,
        id
      )

      return {
        id: doc.$id,
        createdAt: doc.createdAt as string,
        dateRangeStart: doc.dateRangeStart as string,
        dateRangeEnd: doc.dateRangeEnd as string,
        incidentCount: doc.incidentCount as number,
        executiveSummary: doc.executiveSummary as string,
        patternAnalysis: doc.patternAnalysis as string,
        trendAnalysis: doc.trendAnalysis as string,
        riskAssessment: doc.riskAssessment as string,
        recommendations: doc.recommendations as string,
        threatLevel: doc.threatLevel as 'low' | 'medium' | 'high' | 'critical',
        modelUsed: doc.modelUsed as string,
      }
    },

    async getReports(
      options: PaginationOptions
    ): Promise<PaginatedResult<AIReport>> {
      const queries = buildPaginationQueries(options)

      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.AI_REPORTS,
        queries
      )

      const limit = options.limit || 25
      const page = options.page || 1

      return {
        data: response.documents.map((doc) => ({
          id: doc.$id,
          createdAt: doc.createdAt as string,
          dateRangeStart: doc.dateRangeStart as string,
          dateRangeEnd: doc.dateRangeEnd as string,
          incidentCount: doc.incidentCount as number,
          executiveSummary: doc.executiveSummary as string,
          patternAnalysis: doc.patternAnalysis as string,
          trendAnalysis: doc.trendAnalysis as string,
          riskAssessment: doc.riskAssessment as string,
          recommendations: doc.recommendations as string,
          threatLevel: doc.threatLevel as 'low' | 'medium' | 'high' | 'critical',
          modelUsed: doc.modelUsed as string,
        })),
        total: response.total,
        page,
        limit,
        hasMore: page * limit < response.total,
      }
    },

    // ════════════════ Settings ═════════════════════════════

    async getSetting(key: string): Promise<string | null> {
      try {
        const doc = await databases.getDocument(
          databaseId,
          COLLECTIONS.SETTINGS,
          key
        )
        return doc.value as string
      } catch {
        return null
      }
    },

    async setSetting(key: string, value: string): Promise<void> {
      try {
        await databases.getDocument(databaseId, COLLECTIONS.SETTINGS, key)
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.SETTINGS,
          key,
          { value }
        )
      } catch {
        await databases.createDocument(
          databaseId,
          COLLECTIONS.SETTINGS,
          key,
          { key, value }
        )
      }
    },

    async getAllSettings(): Promise<Record<string, string>> {
      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.SETTINGS,
        [Query.limit(100)]
      )

      const settings: Record<string, string> = {}
      for (const doc of response.documents) {
        settings[doc.key as string] = doc.value as string
      }
      return settings
    },

    // ════════════════ Setup ════════════════════════════════

    async ensureCollections(): Promise<void> {
      console.log('[xpecto-shield] Ensuring Appwrite collections exist...')

      try {
        // Try to create database (may already exist)
        try {
          await databases.create(databaseId, 'Xpecto Shield')
        } catch {
          // Database already exists — ok
        }

        // Collection definitions
        const collections = [
          {
            id: COLLECTIONS.INCIDENTS,
            name: 'Shield Incidents',
            attributes: [
              { key: 'timestamp', type: 'string', size: 30, required: true },
              { key: 'sourceIP', type: 'string', size: 50, required: true },
              { key: 'requestPath', type: 'string', size: 500, required: true },
              { key: 'requestMethod', type: 'string', size: 10, required: true },
              { key: 'attackCategory', type: 'string', size: 20, required: true },
              { key: 'matchedPayload', type: 'string', size: 500, required: true },
              { key: 'confidence', type: 'float', required: true },
              { key: 'rawInput', type: 'string', size: 1000, required: true },
              { key: 'action', type: 'string', size: 10, required: true },
              { key: 'userAgent', type: 'string', size: 500, required: true },
              { key: 'geoLocation', type: 'string', size: 100, required: false },
            ],
            indexes: [
              { key: 'idx_timestamp', type: 'key', attributes: ['timestamp'], orders: ['DESC'] },
              { key: 'idx_sourceIP', type: 'key', attributes: ['sourceIP'] },
              { key: 'idx_category', type: 'key', attributes: ['attackCategory'] },
            ],
          },
          {
            id: COLLECTIONS.BLOCKED_IPS,
            name: 'Shield Blocked IPs',
            attributes: [
              { key: 'ipAddress', type: 'string', size: 50, required: true },
              { key: 'reason', type: 'string', size: 10, required: true },
              { key: 'strikeCount', type: 'integer', required: true },
              { key: 'blockedAt', type: 'string', size: 30, required: true },
              { key: 'expiresAt', type: 'string', size: 30, required: false },
              { key: 'lastAttackCategory', type: 'string', size: 20, required: true },
              { key: 'isActive', type: 'boolean', required: true },
            ],
            indexes: [
              { key: 'idx_ipAddress', type: 'key', attributes: ['ipAddress'] },
              { key: 'idx_isActive', type: 'key', attributes: ['isActive'] },
            ],
          },
          {
            id: COLLECTIONS.AI_REPORTS,
            name: 'Shield AI Reports',
            attributes: [
              { key: 'createdAt', type: 'string', size: 30, required: true },
              { key: 'dateRangeStart', type: 'string', size: 30, required: true },
              { key: 'dateRangeEnd', type: 'string', size: 30, required: true },
              { key: 'incidentCount', type: 'integer', required: true },
              { key: 'executiveSummary', type: 'string', size: 5000, required: true },
              { key: 'patternAnalysis', type: 'string', size: 10000, required: true },
              { key: 'trendAnalysis', type: 'string', size: 10000, required: true },
              { key: 'riskAssessment', type: 'string', size: 5000, required: true },
              { key: 'recommendations', type: 'string', size: 5000, required: true },
              { key: 'threatLevel', type: 'string', size: 10, required: true },
              { key: 'modelUsed', type: 'string', size: 100, required: true },
            ],
          },
          {
            id: COLLECTIONS.SETTINGS,
            name: 'Shield Settings',
            attributes: [
              { key: 'key', type: 'string', size: 100, required: true },
              { key: 'value', type: 'string', size: 5000, required: true },
            ],
          },
        ]

        for (const col of collections) {
          try {
            await databases.createCollection(databaseId, col.id, col.name)
            console.log(`[xpecto-shield] Created collection: ${col.name}`)
          } catch {
            // Collection already exists — ok
          }

          // Create attributes
          for (const attr of col.attributes) {
            try {
              if (attr.type === 'string') {
                await databases.createStringAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.size!,
                  attr.required
                )
              } else if (attr.type === 'integer') {
                await databases.createIntegerAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.required
                )
              } else if (attr.type === 'float') {
                await databases.createFloatAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.required
                )
              } else if (attr.type === 'boolean') {
                await databases.createBooleanAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.required
                )
              }
            } catch {
              // Attribute may already exist — ok
            }
          }

          // Create indexes
          if ('indexes' in col && col.indexes) {
            for (const idx of col.indexes) {
              try {
                await databases.createIndex(
                  databaseId,
                  col.id,
                  idx.key,
                  idx.type as any,
                  idx.attributes,
                  (idx as any).orders
                )
              } catch {
                // Index may already exist — ok
              }
            }
          }
        }

        console.log('[xpecto-shield] ✓ All collections verified/created')
      } catch (error) {
        console.error('[xpecto-shield] Collection setup error:', error)
        throw error
      }
    },
  }

  return shieldClient
}
