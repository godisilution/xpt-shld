import { NextResponse } from 'next/server'
import { getEngine } from '@/lib/engine'

export const dynamic = 'force-dynamic'

export async function GET() {
  try {
    const engine = await getEngine()
    const stats = engine.getStats()
    return NextResponse.json(stats)
  } catch (error) {
    return NextResponse.json(
      { error: 'ENGINE_ERROR', message: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    )
  }
}
