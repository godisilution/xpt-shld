// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Core Type Definitions
// ═══════════════════════════════════════════════════════════════

// ─── Threat Categories ─────────────────────────────────────────

/** Supported attack vector categories */
export type ThreatCategory = 'sqli' | 'xss' | 'lfi' | 'ssrf' | 'path-traversal'

/** All available threat categories */
export const THREAT_CATEGORIES: ThreatCategory[] = [
  'sqli',
  'xss',
  'lfi',
  'ssrf',
  'path-traversal',
]

/** Human-readable labels for each category */
export const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  lfi: 'Local File Inclusion',
  ssrf: 'Server-Side Request Forgery',
  'path-traversal': 'Path Traversal',
}

// ─── Aho-Corasick Types ────────────────────────────────────────

/** A single match result from the Aho-Corasick automaton */
export interface AhoCorasickMatch {
  /** The matched pattern text */
  pattern: string
  /** Which attack category this pattern belongs to */
  category: ThreatCategory
  /** Start index of the match in the input string */
  position: number
  /** Length of the matched pattern */
  length: number
}

// ─── Detection Engine Types ────────────────────────────────────

/** Configuration for creating a detection engine instance */
export interface DetectionEngineConfig {
  /** Directory containing payload .txt files (for development/file-based loading) */
  payloadDir?: string
  /** Which categories to load (default: all) */
  categories?: ThreatCategory[]
  /** Whether pattern matching is case-sensitive (default: false) */
  caseSensitive?: boolean
  /** Minimum confidence score to flag a detection (default: 0.7) */
  confidenceThreshold?: number
  /** Input patterns to never flag as threats */
  whitelist?: string[]
}

/** Result of analyzing input for threats */
export interface DetectionResult {
  /** Whether any threats were detected above the confidence threshold */
  detected: boolean
  /** List of confirmed threat matches */
  threats: ThreatMatch[]
  /** Total scan time in milliseconds */
  scanTimeMs: number
}

/** A single confirmed threat match after hybrid validation */
export interface ThreatMatch {
  /** Attack category */
  category: ThreatCategory
  /** The exact payload pattern that matched */
  matchedPayload: string
  /** Confidence score (0.0 - 1.0) */
  confidence: number
  /** Which input field contained the threat (e.g., 'query.search', 'body.email') */
  inputField: string
  /** The decoded input value after normalization */
  decodedInput: string
  /** The original raw input before any decoding */
  rawInput: string
}

/** Engine runtime statistics */
export interface EngineStats {
  /** Total number of loaded patterns across all categories */
  totalPatterns: number
  /** Pattern count per category */
  categoryCounts: Record<ThreatCategory, number>
  /** Time taken to build the automaton (ms) */
  buildTimeMs: number
  /** Whether the engine is ready to accept scan requests */
  isReady: boolean
}

// ─── Payload Database ──────────────────────────────────────────

/** Loaded and categorized payload patterns */
export interface PayloadDatabase {
  /** Map of pattern string → attack category */
  patterns: Map<string, ThreatCategory>
  /** Total unique pattern count */
  totalCount: number
  /** Count per category */
  categoryCounts: Record<ThreatCategory, number>
}

// ─── Detection Engine Interface ────────────────────────────────

/** The public API for the detection engine */
export interface DetectionEngine {
  /** Analyze a single input string */
  analyze(input: string, fieldName?: string): DetectionResult
  /** Analyze multiple named input fields (e.g., query params, body fields) */
  analyzeMultiple(inputs: Record<string, string>): DetectionResult
  /** Get engine runtime statistics */
  getStats(): EngineStats
}

// ─── Appwrite Config ───────────────────────────────────────────

/** Appwrite connection configuration */
export interface AppwriteConfig {
  /** Appwrite API endpoint (e.g., https://cloud.appwrite.io/v1) */
  endpoint: string
  /** Appwrite project ID */
  projectId: string
  /** Appwrite server API key (with database permissions) */
  apiKey: string
  /** Database ID to use (default: 'xpecto_shield') */
  databaseId?: string
}

// ─── AI Config ─────────────────────────────────────────────────

/** Provider-agnostic AI/LLM configuration (OpenAI-compatible) */
export interface AIConfig {
  /** Base URL of the API (e.g., https://openrouter.ai/api/v1) */
  baseUrl: string
  /** API key for authentication */
  apiKey: string
  /** Model identifier (e.g., google/gemini-2.0-flash) */
  model: string
}

// ─── Middleware Config ─────────────────────────────────────────

/** Full configuration for the shield middleware */
export interface ShieldMiddlewareConfig {
  /** Directory containing payload .txt files */
  payloadDir?: string
  /** Which categories to detect (default: all) */
  categories?: ThreatCategory[]
  /** Minimum confidence to trigger blocking (default: 0.7) */
  confidenceThreshold?: number
  /** Number of strikes before auto-blocking an IP (default: 3) */
  maxStrikes?: number
  /** How long to block an IP in seconds (default: 86400 = 24h) */
  blockDuration?: number
  /** IPs that should never be blocked (default: ['127.0.0.1']) */
  whitelistIPs?: string[]
  /** Appwrite connection config */
  appwrite: AppwriteConfig
  /** AI analytics config (optional — disables AI features if not provided) */
  ai?: AIConfig
  /** URL path patterns to protect (default: ['/*']) */
  protectedPaths?: string[]
  /** URL path patterns to exclude from scanning */
  excludePaths?: string[]
}

// ─── API Config ────────────────────────────────────────────────

/** Configuration for the dashboard API route handler */
export interface ShieldAPIConfig {
  /** Appwrite connection config */
  appwrite: AppwriteConfig
  /** AI analytics config (optional) */
  ai?: AIConfig
  /** Custom auth check function — must return true for admin access */
  authCheck: (req: Request) => Promise<boolean>
}

// ─── Incident Log ──────────────────────────────────────────────

/** A detected attack incident record */
export interface IncidentLog {
  /** Document ID (auto-generated by Appwrite) */
  id?: string
  /** ISO 8601 timestamp of detection */
  timestamp: string
  /** Attacker's IP address */
  sourceIP: string
  /** Request URL path */
  requestPath: string
  /** HTTP method (GET, POST, etc.) */
  requestMethod: string
  /** Detected attack category */
  attackCategory: ThreatCategory
  /** The exact payload that matched */
  matchedPayload: string
  /** Detection confidence score */
  confidence: number
  /** Original input before decoding */
  rawInput: string
  /** Action taken */
  action: 'blocked' | 'logged'
  /** Client User-Agent header */
  userAgent: string
  /** Geographic location if available */
  geoLocation?: string
}

// ─── Blocked IP ────────────────────────────────────────────────

/** A blocked IP address record */
export interface BlockedIP {
  /** Document ID */
  id?: string
  /** The blocked IP address */
  ipAddress: string
  /** Reason for blocking */
  reason: 'auto' | 'manual'
  /** Number of detected attacks from this IP */
  strikeCount: number
  /** ISO 8601 timestamp when the block started */
  blockedAt: string
  /** ISO 8601 timestamp when the block expires (null = permanent) */
  expiresAt: string | null
  /** Most recent attack type from this IP */
  lastAttackCategory: ThreatCategory
  /** Whether the block is currently active */
  isActive: boolean
}

// ─── AI Report ─────────────────────────────────────────────────

/** An AI-generated analytics report */
export interface AIReport {
  /** Document ID */
  id?: string
  /** When the report was generated */
  createdAt: string
  /** Analysis period start */
  dateRangeStart: string
  /** Analysis period end */
  dateRangeEnd: string
  /** Number of incidents analyzed */
  incidentCount: number
  /** AI-generated executive summary */
  executiveSummary: string
  /** JSON string of pattern insights */
  patternAnalysis: string
  /** JSON string of trend data */
  trendAnalysis: string
  /** JSON string of risk scores */
  riskAssessment: string
  /** JSON string of recommendations */
  recommendations: string
  /** Overall threat level assessment */
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  /** Which AI model produced this report */
  modelUsed: string
}

// ─── Pagination ────────────────────────────────────────────────

/** Pagination options for list queries */
export interface PaginationOptions {
  /** Page number (1-indexed, default: 1) */
  page?: number
  /** Items per page (default: 25) */
  limit?: number
  /** Field to sort by */
  sortBy?: string
  /** Sort direction */
  sortOrder?: 'asc' | 'desc'
}

/** Paginated query result */
export interface PaginatedResult<T> {
  /** Result items for this page */
  data: T[]
  /** Total number of items matching the query */
  total: number
  /** Current page number */
  page: number
  /** Items per page */
  limit: number
  /** Whether more pages exist */
  hasMore: boolean
}

// ─── Incident Filters ──────────────────────────────────────────

/** Filters for querying incidents */
export interface IncidentFilters {
  /** Filter by attack category */
  category?: ThreatCategory
  /** Filter by source IP */
  sourceIP?: string
  /** Filter by action taken */
  action?: 'blocked' | 'logged'
  /** Start of date range (ISO 8601) */
  dateFrom?: string
  /** End of date range (ISO 8601) */
  dateTo?: string
  /** Minimum confidence score */
  minConfidence?: number
}

// ─── Incident Stats ────────────────────────────────────────────

/** Aggregated statistics for the dashboard overview */
export interface IncidentStats {
  /** Total detected attacks */
  totalIncidents: number
  /** Total unique blocked IPs */
  totalBlockedIPs: number
  /** Number of currently active threats */
  activeThreats: number
  /** Attack count per category */
  categoryBreakdown: Record<ThreatCategory, number>
  /** Attack count per hour for the last 24h */
  hourlyTimeline: Array<{ hour: string; count: number }>
  /** Top 10 attacker IPs by incident count */
  topAttackerIPs: Array<{ ip: string; count: number; lastCategory: ThreatCategory }>
  /** Average confidence score across all detections */
  averageConfidence: number
}

// ─── Date Range ────────────────────────────────────────────────

/** A date range for time-based queries */
export interface DateRange {
  start: string
  end: string
}

// ─── Shield Appwrite Client Interface ──────────────────────────

/** The full Appwrite client interface for Xpecto Shield */
export interface ShieldAppwriteClient {
  // Incidents
  logIncident(incident: IncidentLog): Promise<void>
  getIncidents(
    options: PaginationOptions & { filters?: IncidentFilters }
  ): Promise<PaginatedResult<IncidentLog>>
  getIncidentStats(dateRange?: DateRange): Promise<IncidentStats>

  // Blocked IPs
  isIPBlocked(ip: string): Promise<boolean>
  getIPRecord(ip: string): Promise<BlockedIP | null>
  incrementStrike(ip: string, category: ThreatCategory): Promise<number>
  blockIP(ip: string, reason: 'auto' | 'manual', duration?: number): Promise<void>
  unblockIP(ip: string): Promise<void>
  getBlockedIPs(options: PaginationOptions): Promise<PaginatedResult<BlockedIP>>

  // AI Reports
  saveReport(report: AIReport): Promise<string>
  getReport(id: string): Promise<AIReport>
  getReports(options: PaginationOptions): Promise<PaginatedResult<AIReport>>

  // Settings
  getSetting(key: string): Promise<string | null>
  setSetting(key: string, value: string): Promise<void>
  getAllSettings(): Promise<Record<string, string>>

  // Setup
  ensureCollections(): Promise<void>
}
