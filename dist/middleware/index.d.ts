import { NextRequest } from 'next/server';
import { g as IncidentLog, l as ShieldMiddlewareConfig, T as ThreatCategory } from '../types-wAOtwm6s.js';

/** The middleware function type */
type ShieldMiddleware = (request: NextRequest) => Promise<Response | void>;
/** Incident callback for external logging */
type IncidentCallback = (incident: IncidentLog) => Promise<void>;
/**
 * Create the Xpecto Shield middleware.
 *
 * @param config - Full middleware configuration
 * @param onIncident - Optional callback invoked for each detected incident
 * @returns An async middleware function compatible with Next.js
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { createShieldMiddleware } from 'xpecto-shield/middleware'
 *
 * const shield = await createShieldMiddleware({
 *   payloadDir: './payloads',
 *   appwrite: { ... },
 *   protectedPaths: ['/api/*', '/auth/*'],
 * })
 *
 * export async function middleware(request: NextRequest) {
 *   const response = await shield(request)
 *   if (response) return response
 *   return NextResponse.next()
 * }
 * ```
 */
declare function createShieldMiddleware(config: ShieldMiddlewareConfig, onIncident?: IncidentCallback): Promise<ShieldMiddleware>;
/**
 * Create the Shield middleware from pre-compiled payload data.
 * This is the recommended approach for serverless deployments.
 */
declare function createShieldMiddlewareFromCompiled(compiledData: Record<string, ThreatCategory>, config: ShieldMiddlewareConfig, onIncident?: IncidentCallback): Promise<ShieldMiddleware>;

/**
 * Extract all scannable input fields from a Next.js Request.
 *
 * @param request - The incoming HTTP Request
 * @returns Record of field name → value for all scannable inputs
 */
declare function extractRequestInputs(request: Request): Promise<Record<string, string>>;
/**
 * Extract the client IP from request headers.
 * Checks common proxy headers before falling back.
 */
declare function extractClientIP(request: Request): string;
/**
 * Check if a URL path matches any pattern in a list.
 * Supports simple glob patterns:
 * - `/*` matches everything
 * - `/api/*` matches /api/anything
 * - `/exact` matches exactly
 */
declare function matchesPath(urlPath: string, patterns: string[]): boolean;

/**
 * Build a 403 Forbidden response for a blocked request.
 *
 * @param category - The detected attack category
 * @param clientIP - The requesting client's IP address
 * @returns A Response object with status 403 and styled HTML body
 */
declare function buildBlockResponse(category: ThreatCategory, clientIP: string): Response;
/**
 * Build a JSON 403 response for API endpoints.
 */
declare function buildBlockResponseJSON(category: ThreatCategory, clientIP: string): Response;
/**
 * Check if the request expects a JSON response.
 */
declare function isJSONRequest(request: Request): boolean;

export { type IncidentCallback, type ShieldMiddleware, ShieldMiddlewareConfig, buildBlockResponse, buildBlockResponseJSON, createShieldMiddleware, createShieldMiddlewareFromCompiled, extractClientIP, extractRequestInputs, isJSONRequest, matchesPath };
