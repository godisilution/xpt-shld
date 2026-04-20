// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Payload Loader
// ═══════════════════════════════════════════════════════════════
//
// Loads attack payload patterns from .txt files and builds
// the PayloadDatabase used by the detection engine.
// ═══════════════════════════════════════════════════════════════

import { readFileSync, existsSync } from 'fs'
import { join } from 'path'
import type { ThreatCategory, PayloadDatabase } from './types'
import { THREAT_CATEGORIES } from './types'

/** Mapping of category → expected filename */
const CATEGORY_FILES: Record<ThreatCategory, string> = {
  sqli: 'sqli.txt',
  xss: 'xss.txt',
  lfi: 'lfi.txt',
  ssrf: 'ssrf.txt',
  'path-traversal': 'path-traversal.txt',
}

/**
 * Load payloads from .txt files in a directory.
 *
 * @param dir - Absolute or relative path to the payloads directory
 * @param categories - Which categories to load (default: all)
 * @returns PayloadDatabase with all loaded patterns
 */
export async function loadPayloadsFromDir(
  dir: string,
  categories: ThreatCategory[] = THREAT_CATEGORIES
): Promise<PayloadDatabase> {
  const patterns = new Map<string, ThreatCategory>()
  const categoryCounts: Record<ThreatCategory, number> = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    'path-traversal': 0,
  }

  for (const category of categories) {
    const filename = CATEGORY_FILES[category]
    const filepath = join(dir, filename)

    if (!existsSync(filepath)) {
      console.warn(
        `[xpecto-shield] Payload file not found: ${filepath} — skipping ${category}`
      )
      continue
    }

    try {
      const content = readFileSync(filepath, 'utf-8')
      const categoryPatterns = parsePayloadFile(content, category)

      for (const [pattern, cat] of categoryPatterns) {
        if (!patterns.has(pattern)) {
          patterns.set(pattern, cat)
          categoryCounts[cat]++
        }
      }
    } catch (error) {
      console.error(
        `[xpecto-shield] Error loading ${filepath}:`,
        error instanceof Error ? error.message : error
      )
    }
  }

  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts,
  }
}

/**
 * Parse a single payload file's content into a Map of patterns.
 *
 * File format:
 * - One payload per line
 * - Lines starting with # are comments
 * - Empty lines are skipped
 * - Lines ending with : are category headers (e.g., "MySQL Blind (Time Based):")
 * - All patterns are lowercased for case-insensitive matching
 *
 * @param content - Raw file content
 * @param category - The threat category for these patterns
 * @returns Map of normalized pattern → category
 */
export function parsePayloadFile(
  content: string,
  category: ThreatCategory
): Map<string, ThreatCategory> {
  const patterns = new Map<string, ThreatCategory>()
  const lines = content.split('\n')

  for (const rawLine of lines) {
    const line = rawLine.trim()

    // Skip empty lines
    if (line.length === 0) continue

    // Skip comments
    if (line.startsWith('#')) continue

    // Skip category headers (lines ending with ":")
    // e.g., "MySQL Blind (Time Based):" or "Error Based:"
    if (line.endsWith(':') && !line.includes(' ') === false && line.length < 100) {
      // Additional check: category headers are typically short descriptive text
      // Don't skip actual payloads that happen to end with ":"
      const hasLettersOnly = /^[A-Za-z0-9\s()_/-]+:$/.test(line)
      if (hasLettersOnly) continue
    }

    // Normalize: lowercase for case-insensitive matching
    const normalized = line.toLowerCase()

    // Skip very short patterns (< 3 chars) as they cause too many false positives
    if (normalized.length < 3) continue

    patterns.set(normalized, category)
  }

  return patterns
}

/**
 * Load payloads from pre-compiled data (for serverless environments
 * where fs access may not be available at runtime).
 *
 * @param compiledData - Pre-compiled patterns as a plain object { pattern: category }
 * @returns PayloadDatabase
 */
export function loadPayloadsFromCompiled(
  compiledData: Record<string, ThreatCategory>
): PayloadDatabase {
  const patterns = new Map<string, ThreatCategory>()
  const categoryCounts: Record<ThreatCategory, number> = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    'path-traversal': 0,
  }

  for (const [pattern, category] of Object.entries(compiledData)) {
    patterns.set(pattern, category)
    categoryCounts[category]++
  }

  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts,
  }
}
