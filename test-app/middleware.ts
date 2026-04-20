import { NextRequest, NextResponse } from 'next/server'

const strikeCache = new Map<string, { count: number; lastStrike: number }>()
const blockCache = new Set<string>()

function extractClientIP(request: NextRequest): string {
  const headers = ['x-real-ip', 'x-forwarded-for', 'cf-connecting-ip', 'true-client-ip']
  for (const header of headers) {
    const value = request.headers.get(header)
    if (value) return value.split(',')[0].trim()
  }
  return '127.0.0.1'
}

export async function middleware(request: NextRequest) {
  const url = new URL(request.url)

  if (!url.pathname.startsWith('/api/test/search') &&
      !url.pathname.startsWith('/api/test/login') &&
      !url.pathname.startsWith('/api/test/file') &&
      !url.pathname.startsWith('/api/test/proxy') &&
      !url.pathname.startsWith('/api/test/comment')) {
    return NextResponse.next()
  }

  const clientIP = extractClientIP(request)

  if (blockCache.has(clientIP)) {
    return new NextResponse(
      JSON.stringify({
        error: 'REQUEST_BLOCKED',
        message: 'Your IP has been blocked by Xpecto Shield.',
        category: 'blocked-ip',
        timestamp: new Date().toISOString(),
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'X-Shield-Status': 'blocked',
          'X-Shield-Category': 'blocked-ip',
        },
      }
    )
  }

  const inputs: Record<string, string> = {}
  inputs['url.path'] = url.pathname

  for (const [key, value] of url.searchParams.entries()) {
    inputs[`query.${key}`] = value
  }

  const scannableHeaders = ['referer', 'x-forwarded-for', 'x-forwarded-host', 'user-agent', 'origin']
  for (const header of scannableHeaders) {
    const value = request.headers.get(header)
    if (value) inputs[`header.${header}`] = value
  }

  const cookieHeader = request.headers.get('cookie')
  if (cookieHeader) {
    for (const pair of cookieHeader.split(';')) {
      const eqIdx = pair.indexOf('=')
      if (eqIdx === -1) continue
      const key = pair.substring(0, eqIdx).trim()
      const value = pair.substring(eqIdx + 1).trim()
      if (key) inputs[`cookie.${key}`] = value
    }
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    try {
      const contentType = request.headers.get('content-type') || ''
      if (contentType.includes('application/json')) {
        const body = await request.clone().json()
        flattenObject(body, 'body', inputs, 0)
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const text = await request.clone().text()
        const params = new URLSearchParams(text)
        for (const [key, value] of params.entries()) {
          inputs[`body.${key}`] = value
        }
      }
    } catch {}
  }

  try {
    const scanUrl = new URL('/api/test/scan', request.url)
    const scanRes = await fetch(scanUrl.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ inputs }),
    })

    if (!scanRes.ok) return NextResponse.next()

    const result = await scanRes.json()

    if (!result.detected) return NextResponse.next()

    const topThreat = result.threats[0]
    const existing = strikeCache.get(clientIP) || { count: 0, lastStrike: 0 }
    existing.count++
    existing.lastStrike = Date.now()
    strikeCache.set(clientIP, existing)

    if (existing.count >= 3) {
      blockCache.add(clientIP)
    }

    const incidentUrl = new URL('/api/test/log-incident', request.url)
    fetch(incidentUrl.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sourceIP: clientIP,
        requestPath: url.pathname,
        requestMethod: request.method,
        attackCategory: topThreat.category,
        matchedPayload: topThreat.matchedPayload,
        confidence: topThreat.confidence,
        rawInput: topThreat.rawInput,
        userAgent: request.headers.get('user-agent') || 'unknown',
        strikes: existing.count,
      }),
    }).catch(() => {})

    return new NextResponse(
      JSON.stringify({
        error: 'REQUEST_BLOCKED',
        message: 'Your request has been blocked by Xpecto Shield.',
        category: topThreat.category,
        confidence: topThreat.confidence,
        matchedPayload: topThreat.matchedPayload,
        inputField: topThreat.inputField,
        scanTimeMs: result.scanTimeMs,
        strikes: existing.count,
        timestamp: new Date().toISOString(),
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'X-Shield-Status': 'blocked',
          'X-Shield-Category': topThreat.category,
        },
      }
    )
  } catch {
    return NextResponse.next()
  }
}

function flattenObject(obj: unknown, prefix: string, result: Record<string, string>, depth: number) {
  if (depth > 5 || obj === null || obj === undefined) return
  if (typeof obj === 'string') { result[prefix] = obj; return }
  if (typeof obj === 'number' || typeof obj === 'boolean') { result[prefix] = String(obj); return }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length && i < 50; i++) {
      flattenObject(obj[i], `${prefix}[${i}]`, result, depth + 1)
    }
    return
  }
  if (typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      flattenObject(value, `${prefix}.${key}`, result, depth + 1)
    }
  }
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
