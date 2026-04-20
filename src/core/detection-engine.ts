// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Hybrid Detection Engine
// ═══════════════════════════════════════════════════════════════
//
// Two-stage detection pipeline:
//   Stage 1: Aho-Corasick fast pre-filter (O(n+m+z))
//   Stage 2: Precision validation with confidence scoring
//
// This is the core intelligence of Xpecto Shield.
// ═══════════════════════════════════════════════════════════════

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

// ─── Context Keywords for Precision Scoring ────────────────────

/** SQL-related context keywords that boost SQLi confidence */
const SQL_CONTEXT_KEYWORDS = [
  'select', 'insert', 'update', 'delete', 'drop', 'union',
  'from', 'where', 'table', 'database', 'exec', 'execute',
  'having', 'group', 'order', 'alter', 'create', 'truncate',
  'information_schema', 'sysobjects', 'syscolumns',
]

/** XSS-related context keywords */
const XSS_CONTEXT_KEYWORDS = [
  'script', 'javascript', 'onerror', 'onload', 'onclick',
  'onfocus', 'onmouseover', 'eval', 'alert', 'document',
  'window', 'cookie', 'innerhtml', 'outerhtml', 'srcdoc',
  'svg', 'img', 'iframe', 'body', 'input', 'form',
]

/** Path-related context keywords */
const PATH_CONTEXT_KEYWORDS = [
  '..', '/', '\\', 'etc', 'passwd', 'shadow', 'proc',
  'self', 'environ', 'boot.ini', 'win.ini', 'web.config',
]

/** Context keywords per category */
const CONTEXT_KEYWORDS: Partial<Record<ThreatCategory, string[]>> = {
  sqli: SQL_CONTEXT_KEYWORDS,
  xss: XSS_CONTEXT_KEYWORDS,
  'path-traversal': PATH_CONTEXT_KEYWORDS,
  lfi: PATH_CONTEXT_KEYWORDS,
}

// ─── Detection Engine Factory ──────────────────────────────────

/**
 * Create a new detection engine instance.
 *
 * @param config - Engine configuration
 * @returns Promise resolving to a ready-to-use DetectionEngine
 *
 * @example
 * ```typescript
 * const engine = await createDetectionEngine({
 *   payloadDir: './payloads',
 *   confidenceThreshold: 0.7,
 * })
 *
 * const result = engine.analyze("1' OR '1'='1")
 * // → { detected: true, threats: [...], scanTimeMs: 0.5 }
 * ```
 */
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

  // ─── Load Payloads ─────────────────────────────────────────
  let payloadDb: PayloadDatabase

  if (payloadDir) {
    payloadDb = await loadPayloadsFromDir(payloadDir, categories)
  } else {
    // Empty payload database — patterns can be added later
    payloadDb = {
      patterns: new Map(),
      totalCount: 0,
      categoryCounts: {
        sqli: 0,
        xss: 0,
        lfi: 0,
        ssrf: 0,
        'path-traversal': 0,
      },
    }
  }

  // ─── Build Aho-Corasick Automaton ──────────────────────────
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

  // ─── Lowercase the whitelist for matching ──────────────────
  const normalizedWhitelist = whitelist.map((w) => w.toLowerCase())

  // ─── Engine Implementation ─────────────────────────────────
  const engine: DetectionEngine = {
    analyze(input: string, fieldName: string = 'input'): DetectionResult {
      const scanStart = performance.now()

      // Decode input through the evasion-defying pipeline
      const decoded = decodeInput(input)

      // Stage 1: Aho-Corasick fast scan
      const candidates = automaton.search(decoded)

      if (candidates.length === 0) {
        return {
          detected: false,
          threats: [],
          scanTimeMs: performance.now() - scanStart,
        }
      }

      // Stage 2: Precision validation
      const validatedThreats = validateCandidates(
        candidates,
        decoded,
        input,
        fieldName,
        confidenceThreshold,
        normalizedWhitelist
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

// ─── Precision Validation (Stage 2) ────────────────────────────

/**
 * Validate Aho-Corasick candidate matches with contextual scoring.
 * This reduces false positives by considering:
 * - Pattern length vs input length ratio
 * - Contextual keywords surrounding the match
 * - Whitelist patterns
 */
function validateCandidates(
  candidates: AhoCorasickMatch[],
  decodedInput: string,
  rawInput: string,
  fieldName: string,
  threshold: number,
  whitelist: string[]
): ThreatMatch[] {
  const threats: ThreatMatch[] = []
  const seenPatterns = new Set<string>() // Deduplicate

  // Check whitelist — if the entire decoded input matches a whitelist entry, skip all
  for (const safePattern of whitelist) {
    if (decodedInput.includes(safePattern)) {
      return []
    }
  }

  for (const candidate of candidates) {
    // Deduplicate: same pattern appearing multiple times
    if (seenPatterns.has(candidate.pattern)) continue
    seenPatterns.add(candidate.pattern)

    const confidence = calculateConfidence(candidate, decodedInput)

    if (confidence >= threshold) {
      threats.push({
        category: candidate.category,
        matchedPayload: candidate.pattern,
        confidence,
        inputField: fieldName,
        decodedInput: decodedInput.substring(0, 500), // Cap for storage
        rawInput: rawInput.substring(0, 500),
      })
    }
  }

  // Sort by confidence descending
  threats.sort((a, b) => b.confidence - a.confidence)

  return threats
}

/**
 * Calculate confidence score for a single candidate match.
 *
 * Scoring formula:
 * - Base score: 0.6 (any Aho-Corasick match gets this)
 * - Length ratio bonus: 0 to 0.2 (longer patterns relative to input → higher)
 * - Context bonus: 0 to 0.2 (nearby contextual keywords → higher)
 * - Maximum: 1.0
 */
function calculateConfidence(
  match: AhoCorasickMatch,
  decodedInput: string
): number {
  let score = 0.6 // Base score for any Aho-Corasick match

  // ─── Length Ratio Bonus (0 - 0.2) ──────────────────────────
  // Longer patterns matching in shorter inputs = higher confidence
  const lengthRatio = match.length / decodedInput.length
  const lengthBonus = Math.min(lengthRatio * 0.4, 0.2)
  score += lengthBonus

  // ─── Context Bonus (0 - 0.2) ──────────────────────────────
  const contextKeywords = CONTEXT_KEYWORDS[match.category]
  if (contextKeywords) {
    const inputLower = decodedInput.toLowerCase()
    let contextHits = 0

    for (const keyword of contextKeywords) {
      if (inputLower.includes(keyword) && keyword !== match.pattern) {
        contextHits++
      }
    }

    // Each context keyword hit adds up to 0.05, capped at 0.2
    const contextBonus = Math.min(contextHits * 0.05, 0.2)
    score += contextBonus
  }

  // Cap at 1.0
  return Math.min(score, 1.0)
}

/**
 * Create a detection engine from pre-compiled payload data.
 * Used for serverless environments where fs access is limited.
 *
 * @param compiledData - Pre-compiled patterns as { pattern: category }
 * @param config - Additional engine configuration
 * @returns DetectionEngine instance
 */
export async function createDetectionEngineFromCompiled(
  compiledData: Record<string, ThreatCategory>,
  config: Omit<DetectionEngineConfig, 'payloadDir'> = {}
): Promise<DetectionEngine> {
  const payloadDb = loadPayloadsFromCompiled(compiledData)

  const {
    confidenceThreshold = 0.7,
    whitelist = [],
  } = config

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
