import { AhoCorasickAutomaton } from './aho-corasick'
import { decodeInput } from './input-decoder'
import { loadPayloadsFromDir, loadPayloadsFromCompiled } from './payload-loader'
import type {
  DetectionEngine,
  DetectionEngineConfig,
  DetectionResult,
  ThreatMatch,
  ThreatCategory,
  EngineStats,
  AhoCorasickMatch,
  PayloadDatabase,
} from './types'
import { THREAT_CATEGORIES } from './types'

const SQL_CONTEXT_KEYWORDS = [
  'select', 'insert', 'update', 'delete', 'drop', 'union',
  'from', 'where', 'table', 'database', 'exec', 'execute',
  'having', 'group', 'order', 'alter', 'create', 'truncate',
  'information_schema', 'sysobjects', 'syscolumns',
]

const XSS_CONTEXT_KEYWORDS = [
  'script', 'javascript', 'onerror', 'onload', 'onclick',
  'onfocus', 'onmouseover', 'eval', 'alert', 'document',
  'window', 'cookie', 'innerhtml', 'outerhtml', 'srcdoc',
  'svg', 'img', 'iframe', 'body', 'input', 'form',
]

const PATH_CONTEXT_KEYWORDS = [
  '..', '/', '\\', 'etc', 'passwd', 'shadow', 'proc',
  'self', 'environ', 'boot.ini', 'win.ini', 'web.config',
]

const CONTEXT_KEYWORDS: Partial<Record<ThreatCategory, string[]>> = {
  sqli: SQL_CONTEXT_KEYWORDS,
  xss: XSS_CONTEXT_KEYWORDS,
  'path-traversal': PATH_CONTEXT_KEYWORDS,
  lfi: PATH_CONTEXT_KEYWORDS,
}

export async function createDetectionEngine(
  config: DetectionEngineConfig = {}
): Promise<DetectionEngine> {
  const {
    payloadDir,
    categories = THREAT_CATEGORIES,
    confidenceThreshold = 0.7,
    whitelist = [],
  } = config

  const buildStart = performance.now()

  let payloadDb: PayloadDatabase
  if (payloadDir) {
    payloadDb = await loadPayloadsFromDir(payloadDir, categories)
  } else {
    payloadDb = {
      patterns: new Map(),
      totalCount: 0,
      categoryCounts: { sqli: 0, xss: 0, lfi: 0, ssrf: 0, 'path-traversal': 0 },
    }
  }

  const automaton = new AhoCorasickAutomaton()
  for (const [pattern, category] of payloadDb.patterns) {
    automaton.addPattern(pattern, category)
  }
  automaton.build()

  const buildTimeMs = performance.now() - buildStart

  console.log(
    `[xpecto-shield] Detection engine built in ${buildTimeMs.toFixed(1)}ms — ` +
    `${payloadDb.totalCount} patterns loaded across ${categories.length} categories`
  )

  const normalizedWhitelist = whitelist.map((w) => w.toLowerCase())

  const engine: DetectionEngine = {
    analyze(input: string, fieldName: string = 'input'): DetectionResult {
      const scanStart = performance.now()
      const decoded = decodeInput(input)
      const candidates = automaton.search(decoded)

      if (candidates.length === 0) {
        return { detected: false, threats: [], scanTimeMs: performance.now() - scanStart }
      }

      const validatedThreats = validateCandidates(
        candidates, decoded, input, fieldName, confidenceThreshold, normalizedWhitelist
      )

      return {
        detected: validatedThreats.length > 0,
        threats: validatedThreats,
        scanTimeMs: performance.now() - scanStart,
      }
    },

    analyzeMultiple(inputs: Record<string, string>): DetectionResult {
      const scanStart = performance.now()
      const allThreats: ThreatMatch[] = []

      for (const [fieldName, value] of Object.entries(inputs)) {
        if (!value || typeof value !== 'string') continue
        const result = engine.analyze(value, fieldName)
        allThreats.push(...result.threats)
      }

      return {
        detected: allThreats.length > 0,
        threats: allThreats,
        scanTimeMs: performance.now() - scanStart,
      }
    },

    getStats(): EngineStats {
      return {
        totalPatterns: payloadDb.totalCount,
        categoryCounts: { ...payloadDb.categoryCounts },
        buildTimeMs,
        isReady: true,
      }
    },
  }

  return engine
}

function validateCandidates(
  candidates: AhoCorasickMatch[],
  decodedInput: string,
  rawInput: string,
  fieldName: string,
  threshold: number,
  whitelist: string[]
): ThreatMatch[] {
  const threats: ThreatMatch[] = []
  const seenPatterns = new Set<string>()

  for (const safePattern of whitelist) {
    if (decodedInput.includes(safePattern)) return []
  }

  for (const candidate of candidates) {
    if (seenPatterns.has(candidate.pattern)) continue
    seenPatterns.add(candidate.pattern)

    const confidence = calculateConfidence(candidate, decodedInput)

    if (confidence >= threshold) {
      threats.push({
        category: candidate.category,
        matchedPayload: candidate.pattern,
        confidence,
        inputField: fieldName,
        decodedInput: decodedInput.substring(0, 500),
        rawInput: rawInput.substring(0, 500),
      })
    }
  }

  threats.sort((a, b) => b.confidence - a.confidence)
  return threats
}

function calculateConfidence(
  match: AhoCorasickMatch,
  decodedInput: string
): number {
  let score = 0.6

  const lengthRatio = match.length / decodedInput.length
  const lengthBonus = Math.min(lengthRatio * 0.4, 0.2)
  score += lengthBonus

  const contextKeywords = CONTEXT_KEYWORDS[match.category]
  if (contextKeywords) {
    const inputLower = decodedInput.toLowerCase()
    let contextHits = 0

    for (const keyword of contextKeywords) {
      if (inputLower.includes(keyword) && keyword !== match.pattern) {
        contextHits++
      }
    }

    const contextBonus = Math.min(contextHits * 0.05, 0.2)
    score += contextBonus
  }

  return Math.min(score, 1.0)
}

export async function createDetectionEngineFromCompiled(
  compiledData: Record<string, ThreatCategory>,
  config: Omit<DetectionEngineConfig, 'payloadDir'> = {}
): Promise<DetectionEngine> {
  const payloadDb = loadPayloadsFromCompiled(compiledData)
  const { confidenceThreshold = 0.7, whitelist = [] } = config

  const buildStart = performance.now()
  const automaton = new AhoCorasickAutomaton()
  for (const [pattern, category] of payloadDb.patterns) {
    automaton.addPattern(pattern, category)
  }
  automaton.build()
  const buildTimeMs = performance.now() - buildStart

  const normalizedWhitelist = whitelist.map((w) => w.toLowerCase())

  const engine: DetectionEngine = {
    analyze(input: string, fieldName: string = 'input'): DetectionResult {
      const scanStart = performance.now()
      const decoded = decodeInput(input)
      const candidates = automaton.search(decoded)

      if (candidates.length === 0) {
        return { detected: false, threats: [], scanTimeMs: performance.now() - scanStart }
      }

      const validatedThreats = validateCandidates(
        candidates, decoded, input, fieldName, confidenceThreshold, normalizedWhitelist
      )

      return {
        detected: validatedThreats.length > 0,
        threats: validatedThreats,
        scanTimeMs: performance.now() - scanStart,
      }
    },

    analyzeMultiple(inputs: Record<string, string>): DetectionResult {
      const scanStart = performance.now()
      const allThreats: ThreatMatch[] = []

      for (const [fieldName, value] of Object.entries(inputs)) {
        if (!value || typeof value !== 'string') continue
        const result = engine.analyze(value, fieldName)
        allThreats.push(...result.threats)
      }

      return {
        detected: allThreats.length > 0,
        threats: allThreats,
        scanTimeMs: performance.now() - scanStart,
      }
    },

    getStats(): EngineStats {
      return {
        totalPatterns: payloadDb.totalCount,
        categoryCounts: { ...payloadDb.categoryCounts },
        buildTimeMs,
        isReady: true,
      }
    },
  }

  return engine
}
