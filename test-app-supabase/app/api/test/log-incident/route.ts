import { NextRequest, NextResponse } from 'next/server'
import { shieldClient } from '@/lib/shield-client'

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const incident = {
      timestamp: new Date().toISOString(),
      sourceIP: body.sourceIP || '0.0.0.0',
      requestPath: body.requestPath || '/',
      requestMethod: body.requestMethod || 'GET',
      attackCategory: body.attackCategory || 'sqli',
      matchedPayload: (body.matchedPayload || '').substring(0, 500),
      confidence: body.confidence || 0,
      rawInput: (body.rawInput || '').substring(0, 1000),
      action: 'blocked' as const,
      userAgent: (body.userAgent || 'unknown').substring(0, 500),
    }

    try {
      await shieldClient.logIncident(incident)
    } catch {
      console.log('[test-app] Supabase error, incident logged to console only')
      console.log('[test-app] Incident:', JSON.stringify(incident, null, 2))
    }

    return NextResponse.json({ success: true })
  } catch {
    return NextResponse.json({ success: false }, { status: 500 })
  }
}
