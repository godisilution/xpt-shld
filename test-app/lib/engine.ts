import { createDetectionEngine } from 'xpecto-shield/core'
import type { DetectionEngine } from 'xpecto-shield/core'
import path from 'path'

let engineInstance: DetectionEngine | null = null
let enginePromise: Promise<DetectionEngine> | null = null

export async function getEngine(): Promise<DetectionEngine> {
  if (engineInstance) return engineInstance
  if (enginePromise) return enginePromise

  enginePromise = createDetectionEngine({
    payloadDir: path.resolve(process.cwd(), '..', 'payloads'),
    confidenceThreshold: 0.7,
  })

  engineInstance = await enginePromise
  return engineInstance
}
