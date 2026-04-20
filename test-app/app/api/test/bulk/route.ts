import { NextResponse } from 'next/server'
import { getEngine } from '@/lib/engine'
import fs from 'fs'
import path from 'path'

export const dynamic = 'force-dynamic'

const SAFE_INPUTS = [
  "John O'Brien",
  "SELECT a dress size",
  "What's the best restaurant?",
  "My email is user@example.com",
  "Price is $19.99 (or less)",
  "C:\\Users\\John\\Documents\\report.pdf",
  "https://example.com/search?q=hello+world",
  "The <b>quick</b> brown fox",
  "Order #12345 shipped 2/3/2024",
  "DROP me a line when you're free",
]

export async function POST() {
  try {
    const engine = await getEngine()
    const payloadsDir = path.resolve(process.cwd(), '..', 'payloads')

    const categories = ['sqli', 'xss', 'lfi', 'path-traversal', 'ssrf']
    const categoryResults: Record<string, { total: number; detected: number; avgTime: number }> = {}

    for (const cat of categories) {
      const filePath = path.join(payloadsDir, `${cat}.txt`)
      let lines: string[] = []
      try {
        const content = fs.readFileSync(filePath, 'utf-8')
        lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'))
      } catch {
        categoryResults[cat] = { total: 0, detected: 0, avgTime: 0 }
        continue
      }

      const sampleSize = Math.min(20, lines.length)
      const sampled = []
      const step = Math.floor(lines.length / sampleSize)
      for (let i = 0; i < sampleSize; i++) {
        sampled.push(lines[Math.min(i * step, lines.length - 1)])
      }

      let detected = 0
      let totalTime = 0

      for (const payload of sampled) {
        const result = engine.analyze(payload, 'test')
        totalTime += result.scanTimeMs
        if (result.detected) detected++
      }

      categoryResults[cat] = {
        total: sampleSize,
        detected,
        avgTime: totalTime / sampleSize,
      }
    }

    let falsePositives = 0
    let safeAvgTime = 0
    const falsePositiveDetails: string[] = []

    for (const input of SAFE_INPUTS) {
      const result = engine.analyze(input, 'test')
      safeAvgTime += result.scanTimeMs
      if (result.detected) {
        falsePositives++
        falsePositiveDetails.push(`"${input}" -> ${result.threats[0]?.category} (${(result.threats[0]?.confidence * 100).toFixed(0)}%)`)
      }
    }
    safeAvgTime /= SAFE_INPUTS.length

    const stats = engine.getStats()

    return NextResponse.json({
      engineStats: stats,
      categoryResults,
      falsePositiveTest: {
        totalSafe: SAFE_INPUTS.length,
        falsePositives,
        falsePositiveRate: `${((falsePositives / SAFE_INPUTS.length) * 100).toFixed(1)}%`,
        details: falsePositiveDetails,
        avgScanTimeMs: safeAvgTime,
      },
      summary: {
        overallDetectionRate: `${(
          Object.values(categoryResults).reduce((acc, r) => acc + r.detected, 0) /
          Math.max(Object.values(categoryResults).reduce((acc, r) => acc + r.total, 0), 1) * 100
        ).toFixed(1)}%`,
        avgScanTimeMs: (
          Object.values(categoryResults).reduce((acc, r) => acc + r.avgTime, 0) /
          Math.max(Object.values(categoryResults).length, 1)
        ).toFixed(3),
      },
    })
  } catch (error) {
    return NextResponse.json(
      { error: 'BULK_TEST_FAILED', message: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    )
  }
}
