// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Request Analyzer
// ═══════════════════════════════════════════════════════════════
//
// Extracts and flattens all scannable inputs from an HTTP request:
// query params, headers, cookies, body, and URL path.
// ═══════════════════════════════════════════════════════════════

/**
 * Extract all scannable input fields from a Next.js Request.
 *
 * @param request - The incoming HTTP Request
 * @returns Record of field name → value for all scannable inputs
 */
export async function extractRequestInputs(
  request: Request
): Promise<Record<string, string>> {
  const inputs: Record<string, string> = {}
  const url = new URL(request.url)

  // ─── 1. URL Path ─────────────────────────────────────────────
  inputs['url.path'] = url.pathname

  // ─── 2. Query Parameters ────────────────────────────────────
  for (const [key, value] of url.searchParams.entries()) {
    inputs[`query.${key}`] = value
  }

  // ─── 3. Scannable Headers ───────────────────────────────────
  const scannableHeaders = [
    'referer',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-real-ip',
    'user-agent',
    'origin',
  ]

  for (const header of scannableHeaders) {
    const value = request.headers.get(header)
    if (value) {
      inputs[`header.${header}`] = value
    }
  }

  // ─── 4. Cookies ──────────────────────────────────────────────
  const cookieHeader = request.headers.get('cookie')
  if (cookieHeader) {
    const cookies = parseCookieString(cookieHeader)
    for (const [key, value] of Object.entries(cookies)) {
      inputs[`cookie.${key}`] = value
    }
  }

  // ─── 5. Request Body ────────────────────────────────────────
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    try {
      const contentType = request.headers.get('content-type') || ''

      if (contentType.includes('application/json')) {
        const body = await request.clone().json()
        flattenObject(body, 'body', inputs)
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const text = await request.clone().text()
        const params = new URLSearchParams(text)
        for (const [key, value] of params.entries()) {
          inputs[`body.${key}`] = value
        }
      } else if (contentType.includes('multipart/form-data')) {
        try {
          const formData = await request.clone().formData()
          for (const [key, value] of formData.entries()) {
            if (typeof value === 'string') {
              inputs[`body.${key}`] = value
            }
          }
        } catch {
          // formData parsing may fail — skip silently
        }
      } else if (contentType.includes('text/')) {
        const text = await request.clone().text()
        if (text.length > 0 && text.length <= 10000) {
          inputs['body.raw'] = text
        }
      }
    } catch {
      // Body extraction failure — skip silently
    }
  }

  return inputs
}

/**
 * Extract the client IP from request headers.
 * Checks common proxy headers before falling back.
 */
export function extractClientIP(request: Request): string {
  // Standard proxy headers (in order of preference)
  const ipHeaders = [
    'x-real-ip',
    'x-forwarded-for',
    'cf-connecting-ip', // Cloudflare
    'true-client-ip',   // Akamai
  ]

  for (const header of ipHeaders) {
    const value = request.headers.get(header)
    if (value) {
      // x-forwarded-for can contain comma-separated IPs; take the first
      const ip = value.split(',')[0].trim()
      if (ip) return ip
    }
  }

  return '0.0.0.0' // Unknown
}

/**
 * Check if a URL path matches any pattern in a list.
 * Supports simple glob patterns:
 * - `/*` matches everything
 * - `/api/*` matches /api/anything
 * - `/exact` matches exactly
 */
export function matchesPath(
  urlPath: string,
  patterns: string[]
): boolean {
  for (const pattern of patterns) {
    if (pattern === '/*') return true
    if (pattern === urlPath) return true

    // Glob matching: /api/* matches /api/foo, /api/bar/baz
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2)
      if (urlPath === prefix || urlPath.startsWith(prefix + '/')) {
        return true
      }
    }
  }

  return false
}

// ─── Helpers ───────────────────────────────────────────────────

/** Parse a Cookie header string into key-value pairs */
function parseCookieString(cookieStr: string): Record<string, string> {
  const cookies: Record<string, string> = {}
  const pairs = cookieStr.split(';')

  for (const pair of pairs) {
    const eqIndex = pair.indexOf('=')
    if (eqIndex === -1) continue

    const key = pair.substring(0, eqIndex).trim()
    const value = pair.substring(eqIndex + 1).trim()

    if (key) {
      cookies[key] = value
    }
  }

  return cookies
}

/** Flatten a nested object into dot-notation key-value pairs */
function flattenObject(
  obj: unknown,
  prefix: string,
  result: Record<string, string>,
  depth: number = 0
): void {
  if (depth > 5) return // Prevent infinite recursion on deeply nested objects

  if (obj === null || obj === undefined) return

  if (typeof obj === 'string') {
    result[prefix] = obj
    return
  }

  if (typeof obj === 'number' || typeof obj === 'boolean') {
    result[prefix] = String(obj)
    return
  }

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
