// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Multi-Layer Input Decoder
// ═══════════════════════════════════════════════════════════════
//
// Decoding pipeline to defeat common evasion techniques:
// Raw → URL decode → Double URL → HTML entities → Unicode → Null bytes → Result
// ═══════════════════════════════════════════════════════════════

/**
 * Main decoding pipeline — applies all decoding layers sequentially.
 * This is the primary function used by the detection engine before scanning.
 *
 * @param raw - The raw input string from the HTTP request
 * @returns The fully decoded and normalized string
 */
export function decodeInput(raw: string): string {
  if (!raw || raw.length === 0) return raw

  let decoded = raw

  // Layer 1: Double URL decoding (handles %25XX → %XX → char)
  decoded = decodeDoubleURLEncoding(decoded)

  // Layer 2: Standard URL decoding
  decoded = decodeURLEncoding(decoded)

  // Layer 3: HTML entity decoding
  decoded = decodeHTMLEntities(decoded)

  // Layer 4: Unicode normalization (fullwidth → ASCII)
  decoded = normalizeUnicode(decoded)

  // Layer 5: Null byte removal
  decoded = removeNullBytes(decoded)

  // Layer 6: Base64 detection and decoding
  decoded = detectAndDecodeBase64(decoded)

  return decoded
}

/**
 * Decode standard URL percent-encoding (%XX → character).
 *
 * @example decodeURLEncoding("%27") → "'"
 * @example decodeURLEncoding("%3Cscript%3E") → "<script>"
 */
export function decodeURLEncoding(input: string): string {
  try {
    return decodeURIComponent(input)
  } catch {
    // If decodeURIComponent fails (malformed sequences), do manual replacement
    return input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16))
    })
  }
}

/**
 * Decode double URL encoding (%25XX → %XX → character).
 * Attackers use this to bypass single-layer URL decoding.
 *
 * @example decodeDoubleURLEncoding("%2527") → "'"
 * @example decodeDoubleURLEncoding("%253C") → "<"
 */
export function decodeDoubleURLEncoding(input: string): string {
  // Replace %25XX with %XX (decode the outer layer of %25 = %)
  return input.replace(/%25([0-9A-Fa-f]{2})/g, '%$1')
}

/**
 * Decode HTML entities (named, decimal, and hexadecimal).
 *
 * @example decodeHTMLEntities("&lt;script&gt;") → "<script>"
 * @example decodeHTMLEntities("&#39;") → "'"
 * @example decodeHTMLEntities("&#x27;") → "'"
 */
export function decodeHTMLEntities(input: string): string {
  // Named entities mapping
  const namedEntities: Record<string, string> = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&apos;': "'",
    '&#39;': "'",
    '&nbsp;': ' ',
    '&tab;': '\t',
    '&newline;': '\n',
    '&sol;': '/',
    '&bsol;': '\\',
    '&lpar;': '(',
    '&rpar;': ')',
    '&lsqb;': '[',
    '&rsqb;': ']',
    '&lcub;': '{',
    '&rcub;': '}',
    '&semi;': ';',
    '&colon;': ':',
    '&comma;': ',',
    '&period;': '.',
    '&equals;': '=',
    '&plus;': '+',
    '&hyphen;': '-',
    '&ast;': '*',
    '&num;': '#',
    '&excl;': '!',
    '&quest;': '?',
    '&percnt;': '%',
    '&grave;': '`',
    '&tilde;': '~',
    '&Hat;': '^',
    '&vert;': '|',
    '&commat;': '@',
  }

  let result = input

  // Replace named entities
  for (const [entity, char] of Object.entries(namedEntities)) {
    result = result.replaceAll(entity, char)
  }

  // Replace hexadecimal entities: &#xNN; or &#XNN;
  result = result.replace(/&#[xX]([0-9A-Fa-f]+);?/g, (_, hex) => {
    const codePoint = parseInt(hex, 16)
    return codePoint > 0 && codePoint <= 0x10ffff
      ? String.fromCodePoint(codePoint)
      : ''
  })

  // Replace decimal entities: &#NNN;
  result = result.replace(/&#(\d+);?/g, (_, dec) => {
    const codePoint = parseInt(dec, 10)
    return codePoint > 0 && codePoint <= 0x10ffff
      ? String.fromCodePoint(codePoint)
      : ''
  })

  return result
}

/**
 * Normalize Unicode characters — converts fullwidth and special
 * Unicode characters to their ASCII equivalents.
 *
 * @example normalizeUnicode("ＳＥＬＥＣＴＹfullwidth") → "SELECT"
 */
export function normalizeUnicode(input: string): string {
  let result = ''

  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i)

    // Fullwidth ASCII variants (U+FF01 to U+FF5E) → ASCII (U+0021 to U+007E)
    if (code >= 0xff01 && code <= 0xff5e) {
      result += String.fromCharCode(code - 0xfee0)
    }
    // Fullwidth space (U+3000) → ASCII space
    else if (code === 0x3000) {
      result += ' '
    }
    // Keep other characters as-is
    else {
      result += input[i]
    }
  }

  return result
}

/**
 * Remove null bytes and null byte representations.
 * Null bytes can be used to bypass pattern matching in some parsers.
 *
 * @example removeNullBytes("sel%00ect") → "select"
 * @example removeNullBytes("sel\0ect") → "select"
 */
export function removeNullBytes(input: string): string {
  return input
    .replace(/%00/gi, '')
    .replace(/\0/g, '')
    .replace(/\\0/g, '')
    .replace(/\\x00/gi, '')
}

/**
 * Detect and decode base64-encoded segments within the input.
 * Only decodes segments that are at least 16 characters long
 * and consist entirely of valid base64 characters.
 *
 * @example detectAndDecodeBase64("data=c2VsZWN0ICogZnJvbSB1c2Vycw==") 
 *          → "data=select * from users"
 */
export function detectAndDecodeBase64(input: string): string {
  // Match potential base64 strings (min 16 chars, valid charset, optional padding)
  const base64Regex = /[A-Za-z0-9+/]{16,}={0,2}/g

  return input.replace(base64Regex, (match) => {
    try {
      // Validate: must be a multiple of 4 when padded
      const padded = match.length % 4 === 0 ? match : match + '='.repeat(4 - (match.length % 4))

      // Use atob() for base64 decoding (available in Node.js 16+)
      const decoded = atob(padded)

      // Verify the decoded result is printable ASCII (not binary garbage)
      const isPrintable = /^[\x20-\x7E\t\n\r]+$/.test(decoded)

      if (isPrintable && decoded.length >= 4) {
        return decoded
      }

      return match // Return original if not printable
    } catch {
      return match // Return original if decoding fails
    }
  })
}
