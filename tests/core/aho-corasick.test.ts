// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Aho-Corasick Automaton Tests
// ═══════════════════════════════════════════════════════════════

import { describe, it, expect, beforeEach } from 'vitest'
import { AhoCorasickAutomaton } from '../../src/core/aho-corasick'

describe('AhoCorasickAutomaton', () => {
  let ac: AhoCorasickAutomaton

  beforeEach(() => {
    ac = new AhoCorasickAutomaton()
  })

  describe('basic functionality', () => {
    it('should match a single pattern', () => {
      ac.addPattern("SELECT", 'sqli')
      ac.build()

      const matches = ac.search("try SELECT * FROM users")
      expect(matches.length).toBeGreaterThanOrEqual(1)
      expect(matches.some(m => m.pattern === 'select')).toBe(true)
      expect(matches.some(m => m.category === 'sqli')).toBe(true)
    })

    it('should match multiple patterns', () => {
      ac.addPattern("SELECT", 'sqli')
      ac.addPattern("<script>", 'xss')
      ac.addPattern("../etc/passwd", 'lfi')
      ac.build()

      const matches = ac.search("SELECT * FROM t; <script>alert(1)</script> ../etc/passwd")
      
      const categories = new Set(matches.map(m => m.category))
      expect(categories.has('sqli')).toBe(true)
      expect(categories.has('xss')).toBe(true)
      expect(categories.has('lfi')).toBe(true)
    })

    it('should return empty array when no patterns match', () => {
      ac.addPattern("SELECT", 'sqli')
      ac.build()

      const matches = ac.search("hello world, this is a normal string")
      expect(matches).toEqual([])
    })

    it('should return empty array for empty input', () => {
      ac.addPattern("test", 'sqli')
      ac.build()

      const matches = ac.search("")
      expect(matches).toEqual([])
    })
  })

  describe('case insensitivity', () => {
    it('should match case-insensitively', () => {
      ac.addPattern("SELECT", 'sqli')
      ac.build()

      const matches1 = ac.search("select * from users")
      const matches2 = ac.search("SeLeCt * FROM users")
      const matches3 = ac.search("SELECT * FROM users")

      expect(matches1.length).toBeGreaterThan(0)
      expect(matches2.length).toBeGreaterThan(0)
      expect(matches3.length).toBeGreaterThan(0)
    })
  })

  describe('overlapping patterns', () => {
    it('should find overlapping matches', () => {
      ac.addPattern("he", 'xss')
      ac.addPattern("she", 'xss')
      ac.addPattern("his", 'xss')
      ac.addPattern("hers", 'xss')
      ac.build()

      const matches = ac.search("ushers")
      // "she" at position 1, "he" at position 2, "hers" at position 2
      expect(matches.length).toBeGreaterThanOrEqual(2)
    })

    it('should find nested patterns', () => {
      ac.addPattern("or", 'sqli')
      ac.addPattern("' or '", 'sqli')
      ac.build()

      const matches = ac.search("' or '1'='1")
      expect(matches.length).toBeGreaterThanOrEqual(1)
    })
  })

  describe('position tracking', () => {
    it('should report correct match positions', () => {
      ac.addPattern("test", 'sqli')
      ac.build()

      const matches = ac.search("this is a test string")
      expect(matches.length).toBe(1)
      expect(matches[0].position).toBe(10)
      expect(matches[0].length).toBe(4)
    })
  })

  describe('pattern management', () => {
    it('should track pattern count', () => {
      expect(ac.getPatternCount()).toBe(0)

      ac.addPattern("a", 'sqli')
      ac.addPattern("b", 'xss')
      ac.addPattern("c", 'lfi')

      expect(ac.getPatternCount()).toBe(3)
    })

    it('should reset correctly', () => {
      ac.addPattern("test", 'sqli')
      ac.build()

      ac.reset()

      expect(ac.getPatternCount()).toBe(0)
      expect(ac.getIsBuilt()).toBe(false)
    })

    it('should skip empty patterns', () => {
      ac.addPattern("", 'sqli')
      expect(ac.getPatternCount()).toBe(0)
    })

    it('should throw if patterns added after build', () => {
      ac.addPattern("test", 'sqli')
      ac.build()

      expect(() => ac.addPattern("new", 'xss')).toThrow()
    })

    it('should throw if search called before build', () => {
      ac.addPattern("test", 'sqli')

      expect(() => ac.search("test input")).toThrow()
    })
  })

  describe('performance', () => {
    it('should handle 1000+ patterns with fast search', () => {
      // Add 1000 patterns
      for (let i = 0; i < 1000; i++) {
        ac.addPattern(`pattern_${i}_payload`, 'sqli')
      }
      ac.build()

      const start = performance.now()
      const matches = ac.search("this input contains pattern_500_payload somewhere")
      const elapsed = performance.now() - start

      expect(matches.length).toBeGreaterThan(0)
      expect(elapsed).toBeLessThan(5) // Should be < 5ms
    })

    it('should handle long input strings efficiently', () => {
      ac.addPattern("malicious", 'sqli')
      ac.addPattern("attack", 'xss')
      ac.build()

      // 100KB input string
      const longInput = "safe content ".repeat(8000) + "malicious payload here"

      const start = performance.now()
      const matches = ac.search(longInput)
      const elapsed = performance.now() - start

      expect(matches.length).toBeGreaterThan(0)
      expect(elapsed).toBeLessThan(50) // Should be < 50ms for 100KB
    })
  })

  describe('unicode handling', () => {
    it('should handle unicode input', () => {
      ac.addPattern("alert", 'xss')
      ac.build()

      const matches = ac.search("日本語 alert('xss') テスト")
      expect(matches.length).toBeGreaterThan(0)
    })
  })
})
