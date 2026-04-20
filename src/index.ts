// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Root Package Exports
// ═══════════════════════════════════════════════════════════════
//
// Primary entry point for `import { ... } from 'xpecto-shield'`
//
// For tree-shaking, prefer importing from subpaths:
//   import { createDetectionEngine } from 'xpecto-shield/core'
//   import { createShieldMiddleware } from 'xpecto-shield/middleware'
//   import { createShieldAPI } from 'xpecto-shield/api'
//   import { ShieldDashboard } from 'xpecto-shield/dashboard'
// ═══════════════════════════════════════════════════════════════

// Core
export {
  AhoCorasickAutomaton,
  createDetectionEngine,
  createDetectionEngineFromCompiled,
  decodeInput,
  loadPayloadsFromDir,
  loadPayloadsFromCompiled,
  parsePayloadFile,
} from './core'

export type {
  ThreatCategory,
  AhoCorasickMatch,
  DetectionEngineConfig,
  DetectionResult,
  ThreatMatch,
  EngineStats,
  PayloadDatabase,
  DetectionEngine,
} from './core'

// Middleware
export {
  createShieldMiddleware,
  createShieldMiddlewareFromCompiled,
  extractRequestInputs,
  extractClientIP,
  matchesPath,
  buildBlockResponse,
  buildBlockResponseJSON,
} from './middleware'

export type {
  ShieldMiddlewareConfig,
  ShieldMiddleware,
  IncidentCallback,
} from './middleware'

// API
export {
  createAppwriteClient,
  createAIAnalytics,
  createShieldAPI,
} from './api'

export type {
  AppwriteConfig,
  AIConfig,
  ShieldAPIConfig,
  ShieldAppwriteClient,
  IncidentLog,
  BlockedIP,
  AIReport,
  IncidentStats,
  IncidentFilters,
  PaginationOptions,
  PaginatedResult,
  DateRange,
} from './core'

// Dashboard
export { ShieldDashboard } from './dashboard'
export type { ShieldDashboardProps } from './dashboard'
