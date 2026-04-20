import { NextResponse } from 'next/server'
import { shieldClient } from '@/lib/shield-client'
import type { ThreatCategory, IncidentLog } from '@/lib/core/types'

export const dynamic = 'force-dynamic'

const SAMPLE_IPS = [
  '192.168.1.100', '10.0.0.50', '203.0.113.42', '172.16.0.88',
  '198.51.100.15', '45.33.22.11', '91.134.56.78', '185.220.101.33',
]

const SAMPLE_PATHS = [
  '/api/test/search', '/api/test/login', '/api/test/file',
  '/api/test/proxy', '/api/test/comment',
]

const CATEGORIES: ThreatCategory[] = ['sqli', 'xss', 'lfi', 'ssrf', 'path-traversal']

const SAMPLE_PAYLOADS: Record<ThreatCategory, string[]> = {
  sqli: ["' OR '1'='1", "UNION SELECT * FROM users--", "'; DROP TABLE sessions--", "1 AND SLEEP(5)"],
  xss: ["<script>alert(1)</script>", "<img onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)"],
  lfi: ["../../etc/passwd", "/proc/self/environ", "....//....//etc/shadow"],
  ssrf: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://localhost/admin"],
  'path-traversal': ["../../../", "..%2f..%2f..%2f", "..\\..\\..\\"],
}

export async function POST() {
  try {
    const now = Date.now()
    const dayMs = 24 * 60 * 60 * 1000
    let incidentCount = 0

    for (let i = 0; i < 60; i++) {
      const category = CATEGORIES[i % CATEGORIES.length]
      const ip = SAMPLE_IPS[i % SAMPLE_IPS.length]
      const payloads = SAMPLE_PAYLOADS[category]
      const payload = payloads[i % payloads.length]
      const timestamp = new Date(now - Math.random() * dayMs).toISOString()
      const confidence = 0.65 + Math.random() * 0.33

      const incident: IncidentLog = {
        timestamp,
        sourceIP: ip,
        requestPath: SAMPLE_PATHS[i % SAMPLE_PATHS.length],
        requestMethod: i % 3 === 0 ? 'POST' : 'GET',
        attackCategory: category,
        matchedPayload: payload,
        confidence: parseFloat(confidence.toFixed(2)),
        rawInput: payload,
        action: 'blocked',
        userAgent: 'Mozilla/5.0 (Test Seed Agent)',
      }

      try {
        await shieldClient.logIncident(incident)
        incidentCount++
      } catch (err) {
        console.error(`[seed] Failed to log incident ${i}:`, err)
      }
    }

    let blockedCount = 0
    for (let i = 0; i < 3; i++) {
      const ip = SAMPLE_IPS[i]
      try {
        await shieldClient.blockIP(ip, 'auto', 86400)
        blockedCount++
      } catch (err) {
        console.error(`[seed] Failed to block IP ${ip}:`, err)
      }
    }

    return NextResponse.json({
      success: true,
      incidentsCreated: incidentCount,
      ipsBlocked: blockedCount,
    })
  } catch (error) {
    return NextResponse.json(
      { error: 'SEED_FAILED', message: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    )
  }
}
