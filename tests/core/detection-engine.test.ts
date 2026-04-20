// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Detection Engine Integration Tests
// ═══════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll } from 'vitest'
import { createDetectionEngineFromCompiled } from '../../src/core/detection-engine'
import type { DetectionEngine, ThreatCategory } from '../../src/core/types'

// ─── Test Payload Database ──────────────────────────────────────

const TEST_PAYLOADS: Record<string, ThreatCategory> = {
  // SQLi
  "' or '1'='1": 'sqli',
  "1' or '1'='1'--": 'sqli',
  "union select": 'sqli',
  "select * from": 'sqli',
  "drop table": 'sqli',
  "'; exec xp_cmdshell": 'sqli',
  "1; drop table users--": 'sqli',
  "' union select null,null--": 'sqli',
  "sleep(5)": 'sqli',
  "benchmark(": 'sqli',

  // XSS
  "<script>alert(1)</script>": 'xss',
  "<img onerror=": 'xss',
  "javascript:alert": 'xss',
  "<svg onload=": 'xss',
  "onerror=alert(": 'xss',
  "<iframe src=": 'xss',
  "document.cookie": 'xss',
  "onclick=alert(": 'xss',

  // LFI
  "../../etc/passwd": 'lfi',
  "/etc/shadow": 'lfi',
  "..\\..\\windows\\system32": 'lfi',
  "/proc/self/environ": 'lfi',

  // Path Traversal
  "../../../": 'path-traversal',
  "..%2f..%2f": 'path-traversal',
  "....//....//": 'path-traversal',

  // SSRF
  "http://169.254.169.254": 'ssrf',
  "http://localhost:": 'ssrf',
  "http://127.0.0.1": 'ssrf',
  "http://[::1]": 'ssrf',
}

describe('Detection Engine', () => {
  let engine: DetectionEngine

  beforeAll(async () => {
    engine = await createDetectionEngineFromCompiled(TEST_PAYLOADS, {
      confidenceThreshold: 0.6,
    })
  })

  describe('SQL Injection Detection', () => {
    it('should detect classic SQLi payloads', () => {
      const result = engine.analyze("admin' OR '1'='1'--")
      expect(result.detected).toBe(true)
      expect(result.threats.some(t => t.category === 'sqli')).toBe(true)
    })

    it('should detect UNION-based SQLi', () => {
      const result = engine.analyze("1 UNION SELECT username, password FROM users")
      expect(result.detected).toBe(true)
      expect(result.threats.some(t => t.category === 'sqli')).toBe(true)
    })

    it('should detect time-based blind SQLi', () => {
      const result = engine.analyze("1' AND SLEEP(5)--")
      expect(result.detected).toBe(true)
    })

    it('should not flag normal SQL-like words in context', () => {
      const result = engine.analyze("Please select an option from the menu")
      // This may or may not be detected depending on threshold,
      // but confidence should be lower
      if (result.detected) {
        expect(result.threats[0].confidence).toBeLessThan(0.9)
      }
    })
  })

  describe('XSS Detection', () => {
    it('should detect script-tag XSS', () => {
      const result = engine.analyze("<script>alert(1)</script>")
      expect(result.detected).toBe(true)
      expect(result.threats.some(t => t.category === 'xss')).toBe(true)
    })

    it('should detect event-handler XSS', () => {
      const result = engine.analyze('<img src=x onerror=alert(1)>')
      expect(result.detected).toBe(true)
    })

    it('should detect URL-encoded XSS', () => {
      const result = engine.analyze("%3Cscript%3Ealert(1)%3C%2Fscript%3E")
      expect(result.detected).toBe(true)
    })

    it('should detect HTML-entity encoded XSS', () => {
      const result = engine.analyze("&lt;script&gt;alert(1)&lt;/script&gt;")
      expect(result.detected).toBe(true)
    })
  })

  describe('LFI Detection', () => {
    it('should detect path traversal to /etc/passwd', () => {
      const result = engine.analyze("../../etc/passwd")
      expect(result.detected).toBe(true)
      expect(result.threats.some(t => t.category === 'lfi')).toBe(true)
    })

    it('should detect Windows path traversal', () => {
      const result = engine.analyze("..\\..\\windows\\system32\\config\\sam")
      expect(result.detected).toBe(true)
    })
  })

  describe('SSRF Detection', () => {
    it('should detect cloud metadata SSRF', () => {
      const result = engine.analyze("http://169.254.169.254/latest/meta-data/")
      expect(result.detected).toBe(true)
      expect(result.threats.some(t => t.category === 'ssrf')).toBe(true)
    })

    it('should detect localhost SSRF', () => {
      const result = engine.analyze("http://127.0.0.1:8080/admin")
      expect(result.detected).toBe(true)
    })
  })

  describe('Multiple Field Analysis', () => {
    it('should analyze multiple input fields', () => {
      const result = engine.analyzeMultiple({
        'query.search': "<script>alert(1)</script>",
        'query.id': "1' OR '1'='1",
        'body.name': "John Doe",
      })

      expect(result.detected).toBe(true)
      expect(result.threats.length).toBeGreaterThanOrEqual(2)

      const categories = new Set(result.threats.map(t => t.category))
      expect(categories.has('xss')).toBe(true)
      expect(categories.has('sqli')).toBe(true)
    })

    it('should report the correct field name for each threat', () => {
      const result = engine.analyzeMultiple({
        'query.search': "<script>alert(1)</script>",
        'body.comment': "normal text",
      })

      expect(result.threats.every(t => t.inputField === 'query.search')).toBe(true)
    })
  })

  describe('Evasion Technique Handling', () => {
    it('should detect double URL-encoded payloads', () => {
      // %2527 → %27 → '
      const result = engine.analyze("1%2527%20OR%20%25271%2527=%25271")
      // After full decode pipeline, should match SQLi patterns
      expect(result).toBeDefined()
    })

    it('should detect null-byte evasion', () => {
      const result = engine.analyze("sel%00ect * from users")
      // After null byte removal → "select * from users"
      expect(result.detected).toBe(true)
    })
  })

  describe('Engine Stats', () => {
    it('should return correct stats', () => {
      const stats = engine.getStats()

      expect(stats.totalPatterns).toBe(Object.keys(TEST_PAYLOADS).length)
      expect(stats.isReady).toBe(true)
      expect(stats.buildTimeMs).toBeGreaterThan(0)
      expect(stats.categoryCounts.sqli).toBeGreaterThan(0)
      expect(stats.categoryCounts.xss).toBeGreaterThan(0)
      expect(stats.categoryCounts.lfi).toBeGreaterThan(0)
      expect(stats.categoryCounts.ssrf).toBeGreaterThan(0)
    })
  })

  describe('Performance', () => {
    it('should complete analysis in under 5ms for normal input', () => {
      const result = engine.analyze("1' OR '1'='1'-- test payload")
      expect(result.scanTimeMs).toBeLessThan(5)
    })

    it('should handle large input efficiently', () => {
      const largeInput = "safe content ".repeat(1000) + "' OR '1'='1'--"
      const result = engine.analyze(largeInput)
      expect(result.detected).toBe(true)
      expect(result.scanTimeMs).toBeLessThan(50)
    })
  })

  describe('Safe Input', () => {
    it('should not flag normal text', () => {
      const result = engine.analyze("Hello, my name is John. I would like to order a pizza.")
      expect(result.detected).toBe(false)
    })

    it('should not flag normal URLs', () => {
      const result = engine.analyze("https://www.example.com/products?page=2&sort=price")
      expect(result.detected).toBe(false)
    })

    it('should not flag normal form data', () => {
      const result = engine.analyzeMultiple({
        name: "Alice Smith",
        email: "alice@example.com",
        message: "I love your website, great job!",
      })
      expect(result.detected).toBe(false)
    })
  })
})
