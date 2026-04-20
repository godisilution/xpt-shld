import { NextRequest, NextResponse } from 'next/server'
import { getEngine } from '@/lib/engine'

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const engine = await getEngine()

    if (body.inputs && typeof body.inputs === 'object') {
      const result = engine.analyzeMultiple(body.inputs)
      return NextResponse.json(result)
    }

    const payload = body.payload || ''
    const field = body.field || 'input'
    const result = engine.analyze(payload, field)
    return NextResponse.json(result)
  } catch (error) {
    return NextResponse.json(
      { error: 'SCAN_FAILED', message: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    )
  }
}
