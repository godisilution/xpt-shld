// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Response Builder
// ═══════════════════════════════════════════════════════════════
//
// Generates HTTP responses for blocked requests with a styled
// cyberpunk-themed block page.
// ═══════════════════════════════════════════════════════════════

import type { ThreatCategory, CATEGORY_LABELS } from '../core/types'

/**
 * Build a 403 Forbidden response for a blocked request.
 *
 * @param category - The detected attack category
 * @param clientIP - The requesting client's IP address
 * @returns A Response object with status 403 and styled HTML body
 */
export function buildBlockResponse(
  category: ThreatCategory,
  clientIP: string
): Response {
  const html = generateBlockPage(category, clientIP)

  return new Response(html, {
    status: 403,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Shield-Status': 'blocked',
      'X-Shield-Category': category,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  })
}

/**
 * Build a JSON 403 response for API endpoints.
 */
export function buildBlockResponseJSON(
  category: ThreatCategory,
  clientIP: string
): Response {
  return new Response(
    JSON.stringify({
      error: 'REQUEST_BLOCKED',
      message: 'Your request has been blocked by Xpecto Shield.',
      category,
      timestamp: new Date().toISOString(),
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'X-Shield-Status': 'blocked',
        'X-Shield-Category': category,
        'Cache-Control': 'no-store',
      },
    }
  )
}

/**
 * Check if the request expects a JSON response.
 */
export function isJSONRequest(request: Request): boolean {
  const accept = request.headers.get('accept') || ''
  const contentType = request.headers.get('content-type') || ''

  return (
    accept.includes('application/json') ||
    contentType.includes('application/json') ||
    request.url.includes('/api/')
  )
}

// ─── Block Page HTML ───────────────────────────────────────────

const CATEGORY_NAMES: Record<ThreatCategory, string> = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  lfi: 'Local File Inclusion',
  ssrf: 'Server-Side Request Forgery',
  'path-traversal': 'Path Traversal',
}

function generateBlockPage(category: ThreatCategory, clientIP: string): string {
  const categoryName = CATEGORY_NAMES[category]
  const timestamp = new Date().toISOString()
  const incidentId = generateIncidentId()

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied — Xpecto Shield</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@700;900&display=swap');

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0a0a0f;
      color: #e0e0e0;
      font-family: 'JetBrains Mono', monospace;
      overflow: hidden;
    }

    /* Animated grid background */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background: 
        linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      animation: gridScroll 20s linear infinite;
    }

    @keyframes gridScroll {
      0% { transform: translate(0, 0); }
      100% { transform: translate(40px, 40px); }
    }

    .shield-block {
      position: relative;
      max-width: 520px;
      width: 90%;
      background: rgba(10, 10, 20, 0.95);
      border: 1px solid rgba(0, 255, 136, 0.3);
      clip-path: polygon(0 12px, 12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%);
      padding: 2.5rem;
      text-align: center;
    }

    /* Corner accents */
    .shield-block::before,
    .shield-block::after {
      content: '';
      position: absolute;
      width: 40px;
      height: 40px;
      border: 1px solid #00ff88;
    }
    .shield-block::before {
      top: -1px;
      left: -1px;
      border-right: none;
      border-bottom: none;
    }
    .shield-block::after {
      bottom: -1px;
      right: -1px;
      border-left: none;
      border-top: none;
    }

    .shield-icon {
      font-size: 3rem;
      margin-bottom: 1rem;
      animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }

    .shield-title {
      font-family: 'Orbitron', sans-serif;
      font-weight: 900;
      font-size: 1.5rem;
      color: #ff3366;
      text-transform: uppercase;
      letter-spacing: 3px;
      margin-bottom: 0.5rem;
      text-shadow: 0 0 20px rgba(255, 51, 102, 0.5);
    }

    .shield-subtitle {
      font-size: 0.8rem;
      color: rgba(255, 255, 255, 0.4);
      margin-bottom: 1.5rem;
    }

    .shield-category {
      display: inline-block;
      background: rgba(255, 51, 102, 0.15);
      border: 1px solid rgba(255, 51, 102, 0.4);
      color: #ff3366;
      padding: 0.4rem 1rem;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 1.5rem;
      clip-path: polygon(0 4px, 4px 0, 100% 0, 100% calc(100% - 4px), calc(100% - 4px) 100%, 0 100%);
    }

    .shield-message {
      font-size: 0.85rem;
      line-height: 1.6;
      color: rgba(255, 255, 255, 0.6);
      margin-bottom: 1.5rem;
    }

    .shield-details {
      text-align: left;
      background: rgba(0, 255, 136, 0.03);
      border: 1px solid rgba(0, 255, 136, 0.1);
      padding: 1rem;
      font-size: 0.7rem;
      color: rgba(0, 255, 136, 0.7);
      margin-bottom: 1rem;
    }

    .shield-details div {
      padding: 0.2rem 0;
    }

    .shield-details .label {
      color: rgba(255, 255, 255, 0.3);
      display: inline-block;
      width: 100px;
    }

    .shield-footer {
      font-size: 0.65rem;
      color: rgba(255, 255, 255, 0.2);
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding-top: 1rem;
    }

    .neon-line {
      height: 2px;
      background: linear-gradient(90deg, transparent, #00ff88, transparent);
      margin: 1.5rem 0;
      animation: scanLine 3s ease-in-out infinite;
    }

    @keyframes scanLine {
      0%, 100% { opacity: 0.3; }
      50% { opacity: 1; }
    }
  </style>
</head>
<body>
  <div class="shield-block">
    <div class="shield-icon">🛡️</div>
    <div class="shield-title">Access Denied</div>
    <div class="shield-subtitle">Xpecto Shield — Intrusion Detection & Prevention</div>
    
    <div class="shield-category">${categoryName}</div>
    
    <div class="shield-message">
      Your request has been flagged and blocked for containing
      a potentially malicious payload. This incident has been logged.
    </div>

    <div class="neon-line"></div>

    <div class="shield-details">
      <div><span class="label">Incident:</span> ${incidentId}</div>
      <div><span class="label">Timestamp:</span> ${timestamp}</div>
      <div><span class="label">Category:</span> ${categoryName}</div>
      <div><span class="label">Action:</span> BLOCKED</div>
    </div>

    <div class="shield-footer">
      If you believe this is a false positive, contact the site administrator
      with the incident ID above.
    </div>
  </div>
</body>
</html>`
}

/** Generate a short incident ID for the block page */
function generateIncidentId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let id = 'XS-'
  for (let i = 0; i < 8; i++) {
    id += chars[Math.floor(Math.random() * chars.length)]
  }
  return id
}
