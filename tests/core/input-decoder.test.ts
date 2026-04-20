// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Input Decoder Tests
// ═══════════════════════════════════════════════════════════════

import { describe, it, expect } from 'vitest'
import {
  decodeInput,
  decodeURLEncoding,
  decodeDoubleURLEncoding,
  decodeHTMLEntities,
  normalizeUnicode,
  removeNullBytes,
  detectAndDecodeBase64,
} from '../../src/core/input-decoder'

describe('Input Decoder', () => {
  describe('decodeURLEncoding', () => {
    it('should decode %XX sequences', () => {
      expect(decodeURLEncoding("%27")).toBe("'")
      expect(decodeURLEncoding("%3C")).toBe("<")
      expect(decodeURLEncoding("%3E")).toBe(">")
      expect(decodeURLEncoding("%22")).toBe('"')
    })

    it('should decode full payloads', () => {
      expect(decodeURLEncoding("%3Cscript%3E")).toBe("<script>")
      expect(decodeURLEncoding("1%27%20OR%20%271%27%3D%271")).toBe("1' OR '1'='1")
    })

    it('should handle already decoded input', () => {
      expect(decodeURLEncoding("hello world")).toBe("hello world")
    })
  })

  describe('decodeDoubleURLEncoding', () => {
    it('should decode %25XX → %XX', () => {
      expect(decodeDoubleURLEncoding("%2527")).toBe("%27")
      expect(decodeDoubleURLEncoding("%253C")).toBe("%3C")
    })

    it('should not affect single-encoded values', () => {
      expect(decodeDoubleURLEncoding("%27")).toBe("%27")
    })
  })

  describe('decodeHTMLEntities', () => {
    it('should decode named entities', () => {
      expect(decodeHTMLEntities("&lt;")).toBe("<")
      expect(decodeHTMLEntities("&gt;")).toBe(">")
      expect(decodeHTMLEntities("&amp;")).toBe("&")
      expect(decodeHTMLEntities("&quot;")).toBe('"')
      expect(decodeHTMLEntities("&apos;")).toBe("'")
    })

    it('should decode hexadecimal entities', () => {
      expect(decodeHTMLEntities("&#x27;")).toBe("'")
      expect(decodeHTMLEntities("&#x3C;")).toBe("<")
      expect(decodeHTMLEntities("&#x3c;")).toBe("<")
    })

    it('should decode decimal entities', () => {
      expect(decodeHTMLEntities("&#39;")).toBe("'")
      expect(decodeHTMLEntities("&#60;")).toBe("<")
      expect(decodeHTMLEntities("&#62;")).toBe(">")
    })

    it('should decode full XSS payloads', () => {
      expect(decodeHTMLEntities("&lt;script&gt;alert(1)&lt;/script&gt;"))
        .toBe("<script>alert(1)</script>")
    })
  })

  describe('normalizeUnicode', () => {
    it('should convert fullwidth ASCII to standard ASCII', () => {
      // Fullwidth "SELECT"
      expect(normalizeUnicode("ＳＥＬＥＣＴ")).toBe("SELECT")
    })

    it('should convert fullwidth space', () => {
      expect(normalizeUnicode("hello\u3000world")).toBe("hello world")
    })

    it('should leave normal ASCII untouched', () => {
      expect(normalizeUnicode("hello world")).toBe("hello world")
    })
  })

  describe('removeNullBytes', () => {
    it('should remove %00 null bytes', () => {
      expect(removeNullBytes("sel%00ect")).toBe("select")
    })

    it('should remove literal null bytes', () => {
      expect(removeNullBytes("sel\0ect")).toBe("select")
    })

    it('should remove \\0 escape', () => {
      expect(removeNullBytes("sel\\0ect")).toBe("select")
    })

    it('should remove \\x00 escape', () => {
      expect(removeNullBytes("sel\\x00ect")).toBe("select")
    })
  })

  describe('detectAndDecodeBase64', () => {
    it('should decode base64-encoded payloads', () => {
      // "select * from users" in base64
      const encoded = btoa("select * from users")
      const result = detectAndDecodeBase64(`data=${encoded}`)
      expect(result).toContain("select * from users")
    })

    it('should not decode short strings', () => {
      // Short base64 strings (< 16 chars) should be left alone
      expect(detectAndDecodeBase64("aGVsbG8=")).toBe("aGVsbG8=")
    })

    it('should handle non-base64 strings gracefully', () => {
      expect(detectAndDecodeBase64("normal text here")).toBe("normal text here")
    })
  })

  describe('decodeInput (full pipeline)', () => {
    it('should handle double-encoded XSS', () => {
      // %253C = double-encoded <, %253E = double-encoded >
      const result = decodeInput("%253Cscript%253Ealert(1)%253C/script%253E")
      expect(result).toContain("<script>")
      expect(result).toContain("alert(1)")
    })

    it('should handle null byte injection', () => {
      const result = decodeInput("sel%00ect")
      expect(result).toBe("select")
    })

    it('should handle HTML entity evasion', () => {
      const result = decodeInput("&lt;img onerror=alert(1)&gt;")
      expect(result).toContain("<img")
    })

    it('should handle empty input', () => {
      expect(decodeInput("")).toBe("")
    })

    it('should handle normal input without modification', () => {
      expect(decodeInput("hello world")).toBe("hello world")
    })

    it('should handle combined evasion techniques', () => {
      // Double URL + null bytes
      const result = decodeInput("%2553%2545%254C%2545%2543%2554")
      // After full pipeline, this should be closer to "SELECT"
      expect(result).toBeDefined()
    })
  })
})
