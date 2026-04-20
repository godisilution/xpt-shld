export type ThreatCategory = 'sqli' | 'xss' | 'lfi' | 'ssrf' | 'path-traversal'

export const THREAT_CATEGORIES: ThreatCategory[] = [
  'sqli', 'xss', 'lfi', 'ssrf', 'path-traversal',
]

export interface AhoCorasickMatch {
  pattern: string
  category: ThreatCategory
  position: number
  length: number
}

export interface DetectionEngineConfig {
  payloadDir?: string
  categories?: ThreatCategory[]
  caseSensitive?: boolean
  confidenceThreshold?: number
  whitelist?: string[]
}

export interface DetectionResult {
  detected: boolean
  threats: ThreatMatch[]
  scanTimeMs: number
}

export interface ThreatMatch {
  category: ThreatCategory
  matchedPayload: string
  confidence: number
  inputField: string
  decodedInput: string
  rawInput: string
}

export interface EngineStats {
  totalPatterns: number
  categoryCounts: Record<ThreatCategory, number>
  buildTimeMs: number
  isReady: boolean
}

export interface PayloadDatabase {
  patterns: Map<string, ThreatCategory>
  totalCount: number
  categoryCounts: Record<ThreatCategory, number>
}

export interface DetectionEngine {
  analyze(input: string, fieldName?: string): DetectionResult
  analyzeMultiple(inputs: Record<string, string>): DetectionResult
  getStats(): EngineStats
}

export interface IncidentLog {
  id?: string
  timestamp: string
  sourceIP: string
  requestPath: string
  requestMethod: string
  attackCategory: ThreatCategory
  matchedPayload: string
  confidence: number
  rawInput: string
  action: 'blocked' | 'logged'
  userAgent: string
  geoLocation?: string
}

export interface BlockedIP {
  id?: string
  ipAddress: string
  reason: 'auto' | 'manual'
  strikeCount: number
  blockedAt: string
  expiresAt: string | null
  lastAttackCategory: ThreatCategory
  isActive: boolean
}

export interface AIReport {
  id?: string
  createdAt: string
  dateRangeStart: string
  dateRangeEnd: string
  incidentCount: number
  executiveSummary: string
  patternAnalysis: string
  trendAnalysis: string
  riskAssessment: string
  recommendations: string
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  modelUsed: string
}

export interface PaginationOptions {
  page?: number
  limit?: number
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

export interface PaginatedResult<T> {
  data: T[]
  total: number
  page: number
  limit: number
  hasMore: boolean
}

export interface IncidentFilters {
  category?: ThreatCategory
  sourceIP?: string
  action?: 'blocked' | 'logged'
  dateFrom?: string
  dateTo?: string
  minConfidence?: number
}

export interface IncidentStats {
  totalIncidents: number
  totalBlockedIPs: number
  activeThreats: number
  categoryBreakdown: Record<ThreatCategory, number>
  hourlyTimeline: Array<{ hour: string; count: number }>
  topAttackerIPs: Array<{ ip: string; count: number; lastCategory: ThreatCategory }>
  averageConfidence: number
}

export interface DateRange {
  start: string
  end: string
}
