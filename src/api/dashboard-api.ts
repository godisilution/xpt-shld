// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Dashboard API Route Handlers
// ═══════════════════════════════════════════════════════════════
//
// Ready-to-use Next.js API route handlers for the admin dashboard.
// These handle all CRUD operations and AI report generation.
// ═══════════════════════════════════════════════════════════════

import type { ShieldAPIConfig, ThreatCategory, DateRange } from '../core/types'
import { createAppwriteClient } from './appwrite-client'
import { createAIAnalytics } from './ai-analytics'

/**
 * Create API route handlers for the Shield admin dashboard.
 *
 * @param config - API configuration with Appwrite credentials and auth check
 * @returns Object with all route handlers
 *
 * @example
 * ```typescript
 * // app/api/shield/[...slug]/route.ts
 * import { createShieldAPI } from 'xpecto-shield/api'
 *
 * const api = createShieldAPI({
 *   appwrite: { endpoint: '...', projectId: '...', apiKey: '...' },
 *   authCheck: async (req) => { ... },
 * })
 *
 * export const GET = api.handleGET
 * export const POST = api.handlePOST
 * export const DELETE = api.handleDELETE
 * ```
 */
export function createShieldAPI(config: ShieldAPIConfig) {
  const appwriteClient = createAppwriteClient(config.appwrite)
  const aiAnalytics = config.ai ? createAIAnalytics(config.ai) : null

  /** Verify admin authentication */
  async function requireAuth(request: Request): Promise<Response | null> {
    const isAuthed = await config.authCheck(request)
    if (!isAuthed) {
      return new Response(
        JSON.stringify({ error: 'UNAUTHORIZED', message: 'Admin access required.' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      )
    }
    return null // Authenticated
  }

  /** Parse a slug path from the URL */
  function getSlug(request: Request): string[] {
    const url = new URL(request.url)
    const match = url.pathname.match(/\/api\/shield\/(.*)/)
    if (!match) return []
    return match[1].split('/').filter(Boolean)
  }

  return {
    /**
     * GET /api/shield/:resource
     * Resources: stats, incidents, blocked-ips, reports, settings
     */
    async handleGET(request: Request): Promise<Response> {
      const authError = await requireAuth(request)
      if (authError) return authError

      const slug = getSlug(request)
      const url = new URL(request.url)
      const resource = slug[0]

      try {
        switch (resource) {
          case 'stats': {
            const from = url.searchParams.get('from') || undefined
            const to = url.searchParams.get('to') || undefined
            const dateRange: DateRange | undefined =
              from && to ? { start: from, end: to } : undefined

            const stats = await appwriteClient.getIncidentStats(dateRange)
            return jsonResponse(stats)
          }

          case 'incidents': {
            const page = parseInt(url.searchParams.get('page') || '1')
            const limit = parseInt(url.searchParams.get('limit') || '25')
            const category = url.searchParams.get('category') as ThreatCategory | null
            const sourceIP = url.searchParams.get('ip') || undefined
            const dateFrom = url.searchParams.get('from') || undefined
            const dateTo = url.searchParams.get('to') || undefined

            const result = await appwriteClient.getIncidents({
              page,
              limit,
              sortBy: 'timestamp',
              sortOrder: 'desc',
              filters: {
                category: category || undefined,
                sourceIP,
                dateFrom,
                dateTo,
              },
            })
            return jsonResponse(result)
          }

          case 'blocked-ips': {
            const page = parseInt(url.searchParams.get('page') || '1')
            const limit = parseInt(url.searchParams.get('limit') || '25')

            const result = await appwriteClient.getBlockedIPs({ page, limit })
            return jsonResponse(result)
          }

          case 'reports': {
            if (slug[1]) {
              // GET /api/shield/reports/:id
              const report = await appwriteClient.getReport(slug[1])
              return jsonResponse(report)
            }

            const page = parseInt(url.searchParams.get('page') || '1')
            const limit = parseInt(url.searchParams.get('limit') || '10')

            const result = await appwriteClient.getReports({ page, limit })
            return jsonResponse(result)
          }

          case 'settings': {
            const settings = await appwriteClient.getAllSettings()
            return jsonResponse(settings)
          }

          default:
            return jsonResponse({ error: 'NOT_FOUND', message: `Unknown resource: ${resource}` }, 404)
        }
      } catch (error) {
        console.error(`[xpecto-shield] API GET error (${resource}):`, error)
        return jsonResponse({ error: 'INTERNAL_ERROR', message: 'An internal error occurred.' }, 500)
      }
    },

    /**
     * POST /api/shield/:resource
     * Resources: block-ip, unblock-ip, generate-report, settings, setup
     */
    async handlePOST(request: Request): Promise<Response> {
      const authError = await requireAuth(request)
      if (authError) return authError

      const slug = getSlug(request)
      const resource = slug[0]

      try {
        switch (resource) {
          case 'block-ip': {
            const body = await request.json()
            const { ip, duration } = body as { ip: string; duration?: number }

            if (!ip) {
              return jsonResponse({ error: 'INVALID_INPUT', message: 'IP address required.' }, 400)
            }

            await appwriteClient.blockIP(ip, 'manual', duration)
            return jsonResponse({ success: true, message: `Blocked IP: ${ip}` })
          }

          case 'unblock-ip': {
            const body = await request.json()
            const { ip } = body as { ip: string }

            if (!ip) {
              return jsonResponse({ error: 'INVALID_INPUT', message: 'IP address required.' }, 400)
            }

            await appwriteClient.unblockIP(ip)
            return jsonResponse({ success: true, message: `Unblocked IP: ${ip}` })
          }

          case 'generate-report': {
            if (!aiAnalytics) {
              return jsonResponse(
                { error: 'AI_NOT_CONFIGURED', message: 'AI analytics is not configured.' },
                400
              )
            }

            const body = await request.json()
            const { from, to } = body as { from: string; to: string }

            if (!from || !to) {
              return jsonResponse({ error: 'INVALID_INPUT', message: 'Date range required.' }, 400)
            }

            const dateRange: DateRange = { start: from, end: to }
            const stats = await appwriteClient.getIncidentStats(dateRange)
            const incidents = await appwriteClient.getIncidents({
              page: 1,
              limit: 500,
              filters: { dateFrom: from, dateTo: to },
            })

            const report = await aiAnalytics.generateReport(
              incidents.data,
              stats,
              dateRange
            )

            const reportId = await appwriteClient.saveReport(report)
            return jsonResponse({ success: true, reportId, report })
          }

          case 'settings': {
            const body = await request.json()
            const settings = body as Record<string, string>

            for (const [key, value] of Object.entries(settings)) {
              await appwriteClient.setSetting(key, value)
            }

            return jsonResponse({ success: true, message: 'Settings updated.' })
          }

          case 'setup': {
            await appwriteClient.ensureCollections()
            return jsonResponse({ success: true, message: 'Collections created/verified.' })
          }

          default:
            return jsonResponse({ error: 'NOT_FOUND', message: `Unknown action: ${resource}` }, 404)
        }
      } catch (error) {
        console.error(`[xpecto-shield] API POST error (${resource}):`, error)
        return jsonResponse({ error: 'INTERNAL_ERROR', message: 'An internal error occurred.' }, 500)
      }
    },

    /**
     * DELETE /api/shield/:resource/:id
     */
    async handleDELETE(request: Request): Promise<Response> {
      const authError = await requireAuth(request)
      if (authError) return authError

      const slug = getSlug(request)
      const resource = slug[0]

      try {
        switch (resource) {
          case 'unblock-ip': {
            const ip = slug[1]
            if (!ip) {
              return jsonResponse({ error: 'INVALID_INPUT', message: 'IP address required.' }, 400)
            }

            await appwriteClient.unblockIP(decodeURIComponent(ip))
            return jsonResponse({ success: true, message: `Unblocked IP: ${ip}` })
          }

          default:
            return jsonResponse({ error: 'NOT_FOUND', message: `Unknown resource: ${resource}` }, 404)
        }
      } catch (error) {
        console.error(`[xpecto-shield] API DELETE error (${resource}):`, error)
        return jsonResponse({ error: 'INTERNAL_ERROR', message: 'An internal error occurred.' }, 500)
      }
    },
  }
}

// ─── Helpers ───────────────────────────────────────────────────

function jsonResponse(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  })
}
