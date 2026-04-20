// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Shield Middleware Factory
// ═══════════════════════════════════════════════════════════════
//
// Main entry point for the Next.js middleware integration.
// Creates a middleware function that intercepts requests,
// scans for threats, and blocks malicious traffic.
// ═══════════════════════════════════════════════════════════════

import type { NextRequest } from 'next/server'
import {
  createDetectionEngine,
  createDetectionEngineFromCompiled,
} from '../core/detection-engine'
import type {
  ShieldMiddlewareConfig,
  DetectionEngine,
  ThreatCategory,
  IncidentLog,
} from '../core/types'
import {
  extractRequestInputs,
  extractClientIP,
  matchesPath,
} from './request-analyzer'
import {
  buildBlockResponse,
  buildBlockResponseJSON,
  isJSONRequest,
} from './response-builder'

// ─── In-Memory Strike Counter ──────────────────────────────────
// Used as a fast-path cache before hitting Appwrite
const strikeCache = new Map<string, { count: number; lastStrike: number }>()
const blockCache = new Set<string>()

/** Clear expired entries from the strike cache periodically */
function cleanStrikeCache(blockDuration: number): void {
  const now = Date.now()
  for (const [ip, data] of strikeCache.entries()) {
    if (now - data.lastStrike > blockDuration * 1000) {
      strikeCache.delete(ip)
    }
  }
  for (const ip of blockCache) {
    const strike = strikeCache.get(ip)
    if (!strike || now - strike.lastStrike > blockDuration * 1000) {
      blockCache.delete(ip)
    }
  }
}

// ─── Types ─────────────────────────────────────────────────────

/** The middleware function type */
export type ShieldMiddleware = (
  request: NextRequest
) => Promise<Response | void>

/** Incident callback for external logging */
export type IncidentCallback = (incident: IncidentLog) => Promise<void>

// ─── Middleware Factory ────────────────────────────────────────

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
export async function createShieldMiddleware(
  config: ShieldMiddlewareConfig,
  onIncident?: IncidentCallback
): Promise<ShieldMiddleware> {
  const {
    categories,
    confidenceThreshold = 0.7,
    maxStrikes = 3,
    blockDuration = 86400,
    whitelistIPs = ['127.0.0.1', '::1'],
    protectedPaths = ['/*'],
    excludePaths = [],
  } = config

  // ─── Initialize Detection Engine ──────────────────────────
  let engine: DetectionEngine

  if (config.payloadDir) {
    engine = await createDetectionEngine({
      payloadDir: config.payloadDir,
      categories,
      confidenceThreshold,
    })
  } else {
    // Fallback: create engine with empty patterns (user must provide compiled data)
    engine = await createDetectionEngine({
      categories,
      confidenceThreshold,
    })
  }

  // ─── Periodic Cache Cleanup ────────────────────────────────
  setInterval(() => cleanStrikeCache(blockDuration), 60_000)

  // ─── Log startup ──────────────────────────────────────────
  const stats = engine.getStats()
  console.log(
    `[xpecto-shield] Middleware initialized — ` +
    `${stats.totalPatterns} patterns | ` +
    `threshold: ${confidenceThreshold} | ` +
    `max strikes: ${maxStrikes}`
  )

  // ─── Return Middleware Function ────────────────────────────
  return async function shieldMiddleware(
    request: NextRequest
  ): Promise<Response | void> {
    const url = new URL(request.url)
    const clientIP = extractClientIP(request)

    // ─── Skip excluded paths ──────────────────────────────
    if (excludePaths.length > 0 && matchesPath(url.pathname, excludePaths)) {
      return // Pass through
    }

    // ─── Check if path is protected ───────────────────────
    if (!matchesPath(url.pathname, protectedPaths)) {
      return // Not in protected paths — pass through
    }

    // ─── Skip whitelisted IPs ─────────────────────────────
    if (whitelistIPs.includes(clientIP)) {
      return // Whitelisted — pass through
    }

    // ─── Check block cache (fast path) ────────────────────
    if (blockCache.has(clientIP)) {
      return isJSONRequest(request)
        ? buildBlockResponseJSON('sqli', clientIP)
        : buildBlockResponse('sqli', clientIP)
    }

    // ─── Extract & Analyze Inputs ─────────────────────────
    try {
      const inputs = await extractRequestInputs(request)
      const result = engine.analyzeMultiple(inputs)

      if (!result.detected) {
        return // Clean request — pass through
      }

      // ─── Threat Detected! ─────────────────────────────
      const topThreat = result.threats[0]

      // Update strike count
      const existingStrike = strikeCache.get(clientIP) || { count: 0, lastStrike: 0 }
      existingStrike.count++
      existingStrike.lastStrike = Date.now()
      strikeCache.set(clientIP, existingStrike)

      // Auto-block if strikes exceed threshold
      const shouldBlock = existingStrike.count >= maxStrikes
      if (shouldBlock) {
        blockCache.add(clientIP)
      }

      // Create incident log
      const incident: IncidentLog = {
        timestamp: new Date().toISOString(),
        sourceIP: clientIP,
        requestPath: url.pathname,
        requestMethod: request.method,
        attackCategory: topThreat.category,
        matchedPayload: topThreat.matchedPayload,
        confidence: topThreat.confidence,
        rawInput: topThreat.rawInput,
        action: 'blocked',
        userAgent: request.headers.get('user-agent') || 'unknown',
      }

      // Fire incident callback asynchronously (don't block response)
      if (onIncident) {
        onIncident(incident).catch((err) => {
          console.error('[xpecto-shield] Incident callback error:', err)
        })
      }

      // Log to console
      console.warn(
        `[xpecto-shield] ⚠ BLOCKED | IP: ${clientIP} | ` +
        `Category: ${topThreat.category} | ` +
        `Path: ${url.pathname} | ` +
        `Confidence: ${topThreat.confidence.toFixed(2)} | ` +
        `Strikes: ${existingStrike.count}/${maxStrikes} | ` +
        `Scan: ${result.scanTimeMs.toFixed(1)}ms`
      )

      // Return block response
      return isJSONRequest(request)
        ? buildBlockResponseJSON(topThreat.category, clientIP)
        : buildBlockResponse(topThreat.category, clientIP)

    } catch (error) {
      // Engine error — log but don't block (fail open)
      console.error(
        '[xpecto-shield] Analysis error — passing request through:',
        error instanceof Error ? error.message : error
      )
      return // Fail open
    }
  }
}

/**
 * Create the Shield middleware from pre-compiled payload data.
 * This is the recommended approach for serverless deployments.
 */
export async function createShieldMiddlewareFromCompiled(
  compiledData: Record<string, ThreatCategory>,
  config: ShieldMiddlewareConfig,
  onIncident?: IncidentCallback
): Promise<ShieldMiddleware> {
  const {
    categories,
    confidenceThreshold = 0.7,
    maxStrikes = 3,
    blockDuration = 86400,
    whitelistIPs = ['127.0.0.1', '::1'],
    protectedPaths = ['/*'],
    excludePaths = [],
  } = config

  const engine = await createDetectionEngineFromCompiled(compiledData, {
    categories,
    confidenceThreshold,
  })

  setInterval(() => cleanStrikeCache(blockDuration), 60_000)

  const stats = engine.getStats()
  console.log(
    `[xpecto-shield] Middleware initialized (compiled) — ` +
    `${stats.totalPatterns} patterns | threshold: ${confidenceThreshold}`
  )

  return async function shieldMiddleware(
    request: NextRequest
  ): Promise<Response | void> {
    const url = new URL(request.url)
    const clientIP = extractClientIP(request)

    if (excludePaths.length > 0 && matchesPath(url.pathname, excludePaths)) return
    if (!matchesPath(url.pathname, protectedPaths)) return
    if (whitelistIPs.includes(clientIP)) return
    if (blockCache.has(clientIP)) {
      return isJSONRequest(request)
        ? buildBlockResponseJSON('sqli', clientIP)
        : buildBlockResponse('sqli', clientIP)
    }

    try {
      const inputs = await extractRequestInputs(request)
      const result = engine.analyzeMultiple(inputs)

      if (!result.detected) return

      const topThreat = result.threats[0]
      const existing = strikeCache.get(clientIP) || { count: 0, lastStrike: 0 }
      existing.count++
      existing.lastStrike = Date.now()
      strikeCache.set(clientIP, existing)

      if (existing.count >= maxStrikes) blockCache.add(clientIP)

      const incident: IncidentLog = {
        timestamp: new Date().toISOString(),
        sourceIP: clientIP,
        requestPath: url.pathname,
        requestMethod: request.method,
        attackCategory: topThreat.category,
        matchedPayload: topThreat.matchedPayload,
        confidence: topThreat.confidence,
        rawInput: topThreat.rawInput,
        action: 'blocked',
        userAgent: request.headers.get('user-agent') || 'unknown',
      }

      if (onIncident) {
        onIncident(incident).catch((err) => {
          console.error('[xpecto-shield] Incident callback error:', err)
        })
      }

      console.warn(
        `[xpecto-shield] ⚠ BLOCKED | IP: ${clientIP} | ` +
        `${topThreat.category} | ${url.pathname} | ` +
        `${topThreat.confidence.toFixed(2)} | ${result.scanTimeMs.toFixed(1)}ms`
      )

      return isJSONRequest(request)
        ? buildBlockResponseJSON(topThreat.category, clientIP)
        : buildBlockResponse(topThreat.category, clientIP)

    } catch (error) {
      console.error('[xpecto-shield] Analysis error:', error instanceof Error ? error.message : error)
      return
    }
  }
}
