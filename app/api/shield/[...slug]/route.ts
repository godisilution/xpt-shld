import { shieldClient } from '@/lib/shield-client'
import type { ThreatCategory, DateRange } from '@/lib/core/types'

export const dynamic = 'force-dynamic'

function getSlug(request: Request): string[] {
  const url = new URL(request.url)
  const match = url.pathname.match(/\/api\/shield\/(.*)/)
  if (!match) return []
  return match[1].split('/').filter(Boolean)
}

function jsonResponse(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

export async function GET(request: Request): Promise<Response> {
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
        const stats = await shieldClient.getIncidentStats(dateRange)
        return jsonResponse(stats)
      }

      case 'incidents': {
        const page = parseInt(url.searchParams.get('page') || '1')
        const limit = parseInt(url.searchParams.get('limit') || '25')
        const category = url.searchParams.get('category') as ThreatCategory | null
        const sourceIP = url.searchParams.get('ip') || undefined
        const dateFrom = url.searchParams.get('from') || undefined
        const dateTo = url.searchParams.get('to') || undefined

        const result = await shieldClient.getIncidents({
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
        const result = await shieldClient.getBlockedIPs({ page, limit })
        return jsonResponse(result)
      }

      case 'reports': {
        if (slug[1]) {
          const report = await shieldClient.getReport(slug[1])
          return jsonResponse(report)
        }
        const page = parseInt(url.searchParams.get('page') || '1')
        const limit = parseInt(url.searchParams.get('limit') || '10')
        const result = await shieldClient.getReports({ page, limit })
        return jsonResponse(result)
      }

      case 'settings': {
        const settings = await shieldClient.getAllSettings()
        return jsonResponse(settings)
      }

      default:
        return jsonResponse({ error: 'NOT_FOUND', message: `Unknown resource: ${resource}` }, 404)
    }
  } catch (error) {
    console.error(`[xpecto-shield] API GET error (${resource}):`, error)
    return jsonResponse({ error: 'INTERNAL_ERROR', message: 'An internal error occurred.' }, 500)
  }
}

export async function POST(request: Request): Promise<Response> {
  const slug = getSlug(request)
  const resource = slug[0]

  try {
    switch (resource) {
      case 'block-ip': {
        const body = await request.json()
        const { ip, duration } = body as { ip: string; duration?: number }
        if (!ip) return jsonResponse({ error: 'INVALID_INPUT', message: 'IP address required.' }, 400)
        await shieldClient.blockIP(ip, 'manual', duration)
        return jsonResponse({ success: true, message: `Blocked IP: ${ip}` })
      }

      case 'unblock-ip': {
        const body = await request.json()
        const { ip } = body as { ip: string }
        if (!ip) return jsonResponse({ error: 'INVALID_INPUT', message: 'IP address required.' }, 400)
        await shieldClient.unblockIP(ip)
        return jsonResponse({ success: true, message: `Unblocked IP: ${ip}` })
      }

      case 'settings': {
        const body = await request.json()
        const settings = body as Record<string, string>
        for (const [key, value] of Object.entries(settings)) {
          await shieldClient.setSetting(key, value)
        }
        return jsonResponse({ success: true, message: 'Settings updated.' })
      }

      case 'setup': {
        return jsonResponse({ success: true, message: 'Tables managed via Supabase migrations.' })
      }

      default:
        return jsonResponse({ error: 'NOT_FOUND', message: `Unknown action: ${resource}` }, 404)
    }
  } catch (error) {
    console.error(`[xpecto-shield] API POST error (${resource}):`, error)
    return jsonResponse({ error: 'INTERNAL_ERROR', message: 'An internal error occurred.' }, 500)
  }
}

export async function DELETE(request: Request): Promise<Response> {
  const slug = getSlug(request)
  const resource = slug[0]

  try {
    switch (resource) {
      case 'unblock-ip': {
        const ip = slug[1]
        if (!ip) return jsonResponse({ error: 'INVALID_INPUT', message: 'IP address required.' }, 400)
        await shieldClient.unblockIP(decodeURIComponent(ip))
        return jsonResponse({ success: true, message: `Unblocked IP: ${ip}` })
      }

      default:
        return jsonResponse({ error: 'NOT_FOUND', message: `Unknown resource: ${resource}` }, 404)
    }
  } catch (error) {
    console.error(`[xpecto-shield] API DELETE error (${resource}):`, error)
    return jsonResponse({ error: 'INTERNAL_ERROR', message: 'An internal error occurred.' }, 500)
  }
}
