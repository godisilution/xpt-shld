export function decodeInput(raw: string): string {
  if (!raw || raw.length === 0) return raw

  let decoded = raw
  decoded = decodeDoubleURLEncoding(decoded)
  decoded = decodeURLEncoding(decoded)
  decoded = decodeHTMLEntities(decoded)
  decoded = normalizeUnicode(decoded)
  decoded = removeNullBytes(decoded)
  decoded = detectAndDecodeBase64(decoded)

  return decoded
}

export function decodeURLEncoding(input: string): string {
  try {
    return decodeURIComponent(input)
  } catch {
    return input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16))
    })
  }
}

export function decodeDoubleURLEncoding(input: string): string {
  return input.replace(/%25([0-9A-Fa-f]{2})/g, '%$1')
}

export function decodeHTMLEntities(input: string): string {
  const namedEntities: Record<string, string> = {
    '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
    '&apos;': "'", '&#39;': "'", '&nbsp;': ' ', '&tab;': '\t',
    '&newline;': '\n', '&sol;': '/', '&bsol;': '\\', '&lpar;': '(',
    '&rpar;': ')', '&lsqb;': '[', '&rsqb;': ']', '&lcub;': '{',
    '&rcub;': '}', '&semi;': ';', '&colon;': ':', '&comma;': ',',
    '&period;': '.', '&equals;': '=', '&plus;': '+', '&hyphen;': '-',
    '&ast;': '*', '&num;': '#', '&excl;': '!', '&quest;': '?',
    '&percnt;': '%', '&grave;': '`', '&tilde;': '~', '&Hat;': '^',
    '&vert;': '|', '&commat;': '@',
  }

  let result = input
  for (const [entity, char] of Object.entries(namedEntities)) {
    result = result.replaceAll(entity, char)
  }

  result = result.replace(/&#[xX]([0-9A-Fa-f]+);?/g, (_, hex) => {
    const codePoint = parseInt(hex, 16)
    return codePoint > 0 && codePoint <= 0x10ffff
      ? String.fromCodePoint(codePoint) : ''
  })

  result = result.replace(/&#(\d+);?/g, (_, dec) => {
    const codePoint = parseInt(dec, 10)
    return codePoint > 0 && codePoint <= 0x10ffff
      ? String.fromCodePoint(codePoint) : ''
  })

  return result
}

export function normalizeUnicode(input: string): string {
  let result = ''
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i)
    if (code >= 0xff01 && code <= 0xff5e) {
      result += String.fromCharCode(code - 0xfee0)
    } else if (code === 0x3000) {
      result += ' '
    } else {
      result += input[i]
    }
  }
  return result
}

export function removeNullBytes(input: string): string {
  return input
    .replace(/%00/gi, '')
    .replace(/\0/g, '')
    .replace(/\\0/g, '')
    .replace(/\\x00/gi, '')
}

export function detectAndDecodeBase64(input: string): string {
  const base64Regex = /[A-Za-z0-9+/]{16,}={0,2}/g

  return input.replace(base64Regex, (match) => {
    try {
      const padded = match.length % 4 === 0
        ? match
        : match + '='.repeat(4 - (match.length % 4))
      const decoded = atob(padded)
      const isPrintable = /^[\x20-\x7E\t\n\r]+$/.test(decoded)
      if (isPrintable && decoded.length >= 4) return decoded
      return match
    } catch {
      return match
    }
  })
}
