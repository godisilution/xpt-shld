// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Middleware Module Exports
// ═══════════════════════════════════════════════════════════════

export {
  createShieldMiddleware,
  createShieldMiddlewareFromCompiled,
  type ShieldMiddleware,
  type IncidentCallback,
} from './shield-middleware'
export type { ShieldMiddlewareConfig } from '../core/types'
export { extractRequestInputs, extractClientIP, matchesPath } from './request-analyzer'
export { buildBlockResponse, buildBlockResponseJSON, isJSONRequest } from './response-builder'
