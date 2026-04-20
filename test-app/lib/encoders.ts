export function doubleUrlEncode(input: string): string {
  return encodeURIComponent(encodeURIComponent(input))
}

export function htmlEntityEncode(input: string): string {
  return input.replace(/./g, (char) => `&#${char.charCodeAt(0)};`)
}

export function unicodeFullwidth(input: string): string {
  return input.replace(/[!-~]/g, (char) => {
    return String.fromCharCode(char.charCodeAt(0) + 0xfee0)
  })
}

export function base64Encode(input: string): string {
  return btoa(input)
}

export function nullByteInject(input: string): string {
  if (input.length < 2) return input
  const mid = Math.floor(input.length / 2)
  return input.slice(0, mid) + '%00' + input.slice(mid)
}

export type EncoderKey = 'double-url' | 'html-entity' | 'unicode-fullwidth' | 'base64' | 'null-byte'

export const ENCODERS: Record<EncoderKey, { label: string; fn: (s: string) => string }> = {
  'double-url': { label: 'Double URL Encode', fn: doubleUrlEncode },
  'html-entity': { label: 'HTML Entity Encode', fn: htmlEntityEncode },
  'unicode-fullwidth': { label: 'Unicode Fullwidth', fn: unicodeFullwidth },
  'base64': { label: 'Base64 Encode', fn: base64Encode },
  'null-byte': { label: 'Null Byte Inject', fn: nullByteInject },
}
