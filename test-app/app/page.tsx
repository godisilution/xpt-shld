'use client'

import { useState, useCallback } from 'react'
import { PRESET_PAYLOADS, CATEGORY_LABELS, CATEGORY_COLORS } from '@/lib/payloads'
import type { PresetPayload } from '@/lib/payloads'
import { ENCODERS } from '@/lib/encoders'
import type { EncoderKey } from '@/lib/encoders'

interface TestResult {
  id: number
  payload: string
  encodedPayload: string
  target: string
  method: string
  status: number
  blocked: boolean
  category?: string
  confidence?: number
  matchedPayload?: string
  inputField?: string
  scanTimeMs?: number
  strikes?: number
  responseTimeMs: number
  timestamp: string
}

type TargetEndpoint = 'search' | 'login' | 'file' | 'proxy' | 'comment'

const TARGET_INFO: Record<TargetEndpoint, { path: string; description: string }> = {
  search: { path: '/api/test/search', description: 'GET ?q= (SQLi, XSS)' },
  login: { path: '/api/test/login', description: 'POST {username, password} (SQLi)' },
  file: { path: '/api/test/file', description: 'GET ?path= (LFI, Path Traversal)' },
  proxy: { path: '/api/test/proxy', description: 'POST {url} (SSRF)' },
  comment: { path: '/api/test/comment', description: 'POST {content} (XSS)' },
}

export default function SimulatorPage() {
  const [results, setResults] = useState<TestResult[]>([])
  const [customPayload, setCustomPayload] = useState('')
  const [customTarget, setCustomTarget] = useState<TargetEndpoint>('search')
  const [activeEncoders, setActiveEncoders] = useState<Set<EncoderKey>>(new Set())
  const [sending, setSending] = useState(false)
  const [resultIdCounter, setResultIdCounter] = useState(0)

  const toggleEncoder = (key: EncoderKey) => {
    setActiveEncoders(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const applyEncoders = useCallback((input: string): string => {
    let result = input
    for (const key of activeEncoders) {
      result = ENCODERS[key].fn(result)
    }
    return result
  }, [activeEncoders])

  const sendAttack = useCallback(async (payload: string, target: TargetEndpoint, method: 'GET' | 'POST') => {
    setSending(true)
    const encoded = applyEncoders(payload)
    const startTime = performance.now()

    try {
      let response: Response

      if (method === 'GET') {
        const paramKey = target === 'file' ? 'path' : 'q'
        response = await fetch(`${TARGET_INFO[target].path}?${paramKey}=${encodeURIComponent(encoded)}`, {
          headers: { 'Content-Type': 'application/json' },
        })
      } else {
        const bodyMap: Record<string, Record<string, string>> = {
          login: { username: encoded, password: 'test123' },
          proxy: { url: encoded },
          comment: { content: encoded },
        }
        response = await fetch(TARGET_INFO[target].path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(bodyMap[target] || { input: encoded }),
        })
      }

      const responseTimeMs = performance.now() - startTime
      let data: Record<string, unknown> = {}
      try { data = await response.json() } catch {}

      const newResult: TestResult = {
        id: resultIdCounter,
        payload,
        encodedPayload: encoded !== payload ? encoded : '',
        target,
        method,
        status: response.status,
        blocked: response.status === 403,
        category: data.category as string | undefined,
        confidence: data.confidence as number | undefined,
        matchedPayload: data.matchedPayload as string | undefined,
        inputField: data.inputField as string | undefined,
        scanTimeMs: data.scanTimeMs as number | undefined,
        strikes: data.strikes as number | undefined,
        responseTimeMs,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
      }

      setResultIdCounter(prev => prev + 1)
      setResults(prev => [newResult, ...prev.slice(0, 49)])
    } catch (err) {
      const responseTimeMs = performance.now() - startTime
      setResults(prev => [{
        id: resultIdCounter,
        payload,
        encodedPayload: encoded !== payload ? encoded : '',
        target,
        method,
        status: 0,
        blocked: false,
        responseTimeMs,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
      }, ...prev.slice(0, 49)])
      setResultIdCounter(prev => prev + 1)
    } finally {
      setSending(false)
    }
  }, [applyEncoders, resultIdCounter])

  const handlePreset = (preset: PresetPayload) => {
    sendAttack(preset.payload, preset.target, preset.method)
  }

  const handleCustom = () => {
    if (!customPayload.trim()) return
    const method = customTarget === 'search' || customTarget === 'file' ? 'GET' : 'POST'
    sendAttack(customPayload, customTarget, method)
  }

  const blockedCount = results.filter(r => r.blocked).length
  const passedCount = results.filter(r => !r.blocked && r.status > 0).length

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{
          fontFamily: 'var(--shield-font-heading)',
          fontWeight: 900,
          fontSize: '1.5rem',
          textTransform: 'uppercase',
          letterSpacing: '3px',
        }}>
          Attack Simulator
        </h1>
        <p style={{
          fontFamily: 'var(--shield-font-accent)',
          fontSize: '0.75rem',
          color: 'var(--shield-muted-fg)',
          textTransform: 'uppercase',
          letterSpacing: '2px',
          marginTop: '0.25rem',
        }}>
          Test IDPS Detection // Payload Injection Testing
        </p>
      </div>

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        <StatCard label="Tests Run" value={results.length} color="var(--shield-accent)" />
        <StatCard label="Blocked" value={blockedCount} color="var(--shield-destructive)" />
        <StatCard label="Passed" value={passedCount} color="var(--shield-warning)" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Left: Attack Payloads */}
        <div>
          {/* Custom Payload */}
          <div style={{
            background: 'var(--shield-card)',
            border: '1px solid var(--shield-border)',
            padding: '1.25rem',
            marginBottom: '1rem',
          }}>
            <div style={{
              fontFamily: 'var(--shield-font-heading)',
              fontWeight: 700,
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '2px',
              color: 'var(--shield-muted-fg)',
              marginBottom: '0.75rem',
            }}>
              Custom Payload
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <div style={{ flex: 1, position: 'relative' }}>
                <span style={{
                  position: 'absolute',
                  left: '0.75rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--shield-accent)',
                  fontFamily: 'var(--shield-font-body)',
                  fontSize: '0.85rem',
                  pointerEvents: 'none',
                }}>&gt;</span>
                <input
                  type="text"
                  value={customPayload}
                  onChange={(e) => setCustomPayload(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCustom()}
                  placeholder="Enter payload..."
                  style={{
                    width: '100%',
                    padding: '0.6rem 1rem 0.6rem 2rem',
                    background: 'var(--shield-input)',
                    border: '1px solid var(--shield-border)',
                    color: 'var(--shield-accent)',
                    fontFamily: 'var(--shield-font-body)',
                    fontSize: '0.8rem',
                  }}
                />
              </div>
              <select
                value={customTarget}
                onChange={(e) => setCustomTarget(e.target.value as TargetEndpoint)}
                style={{
                  padding: '0.6rem',
                  background: 'var(--shield-input)',
                  border: '1px solid var(--shield-border)',
                  color: 'var(--shield-fg)',
                  fontFamily: 'var(--shield-font-body)',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  width: '120px',
                }}
              >
                {Object.entries(TARGET_INFO).map(([key, info]) => (
                  <option key={key} value={key}>{key}</option>
                ))}
              </select>
            </div>
            <button
              onClick={handleCustom}
              disabled={sending || !customPayload.trim()}
              style={{
                fontFamily: 'var(--shield-font-accent)',
                fontSize: '0.7rem',
                textTransform: 'uppercase',
                letterSpacing: '2px',
                padding: '0.5rem 1.25rem',
                border: '2px solid var(--shield-destructive)',
                background: 'transparent',
                color: 'var(--shield-destructive)',
                cursor: 'pointer',
                transition: 'all 150ms',
                opacity: sending ? 0.5 : 1,
              }}
            >
              {sending ? 'Sending...' : 'Fire Payload'}
            </button>
          </div>

          {/* Evasion Encoders */}
          <div style={{
            background: 'var(--shield-card)',
            border: '1px solid var(--shield-border)',
            padding: '1.25rem',
            marginBottom: '1rem',
          }}>
            <div style={{
              fontFamily: 'var(--shield-font-heading)',
              fontWeight: 700,
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '2px',
              color: 'var(--shield-muted-fg)',
              marginBottom: '0.75rem',
            }}>
              Evasion Techniques
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {(Object.entries(ENCODERS) as [EncoderKey, { label: string }][]).map(([key, enc]) => {
                const active = activeEncoders.has(key)
                return (
                  <button
                    key={key}
                    onClick={() => toggleEncoder(key)}
                    style={{
                      fontFamily: 'var(--shield-font-accent)',
                      fontSize: '0.6rem',
                      textTransform: 'uppercase',
                      letterSpacing: '1.5px',
                      padding: '0.35rem 0.75rem',
                      border: `1px solid ${active ? 'var(--shield-accent-tertiary)' : 'var(--shield-border)'}`,
                      background: active ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                      color: active ? 'var(--shield-accent-tertiary)' : 'var(--shield-muted-fg)',
                      cursor: 'pointer',
                      transition: 'all 150ms',
                    }}
                  >
                    {enc.label}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Preset Payloads */}
          {Object.entries(PRESET_PAYLOADS).map(([category, presets]) => (
            <div
              key={category}
              style={{
                background: 'var(--shield-card)',
                border: '1px solid var(--shield-border)',
                padding: '1.25rem',
                marginBottom: '1rem',
              }}
            >
              <div style={{
                fontFamily: 'var(--shield-font-heading)',
                fontWeight: 700,
                fontSize: '0.7rem',
                textTransform: 'uppercase',
                letterSpacing: '2px',
                color: CATEGORY_COLORS[category] || 'var(--shield-muted-fg)',
                marginBottom: '0.75rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}>
                <span style={{
                  width: 8,
                  height: 8,
                  background: CATEGORY_COLORS[category],
                  display: 'inline-block',
                }} />
                {CATEGORY_LABELS[category]}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {presets.map((preset, i) => (
                  <button
                    key={i}
                    onClick={() => handlePreset(preset)}
                    disabled={sending}
                    title={preset.payload}
                    style={{
                      fontFamily: 'var(--shield-font-accent)',
                      fontSize: '0.6rem',
                      textTransform: 'uppercase',
                      letterSpacing: '1px',
                      padding: '0.35rem 0.75rem',
                      border: `1px solid ${CATEGORY_COLORS[category]}40`,
                      background: `${CATEGORY_COLORS[category]}10`,
                      color: CATEGORY_COLORS[category],
                      cursor: 'pointer',
                      transition: 'all 150ms',
                      opacity: sending ? 0.5 : 1,
                    }}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Right: Results */}
        <div>
          <div style={{
            background: 'var(--shield-card)',
            border: '1px solid var(--shield-border)',
            padding: '1.25rem',
            maxHeight: 'calc(100vh - 200px)',
            overflowY: 'auto',
          }}>
            <div style={{
              fontFamily: 'var(--shield-font-heading)',
              fontWeight: 700,
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '2px',
              color: 'var(--shield-muted-fg)',
              marginBottom: '1rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <span>Test Results</span>
              {results.length > 0 && (
                <button
                  onClick={() => setResults([])}
                  style={{
                    fontFamily: 'var(--shield-font-accent)',
                    fontSize: '0.55rem',
                    textTransform: 'uppercase',
                    letterSpacing: '1px',
                    padding: '0.25rem 0.5rem',
                    border: 'none',
                    background: 'transparent',
                    color: 'var(--shield-muted-fg)',
                    cursor: 'pointer',
                  }}
                >
                  Clear
                </button>
              )}
            </div>

            {results.length === 0 ? (
              <div style={{
                textAlign: 'center',
                padding: '3rem 1rem',
                color: 'var(--shield-muted-fg)',
              }}>
                <div style={{ fontSize: '2rem', marginBottom: '0.75rem', opacity: 0.4 }}>
                  &gt;_
                </div>
                <div style={{
                  fontFamily: 'var(--shield-font-accent)',
                  fontSize: '0.7rem',
                  textTransform: 'uppercase',
                  letterSpacing: '2px',
                }}>
                  No tests run yet
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {results.map((result) => (
                  <ResultCard key={result.id} result={result} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      background: 'var(--shield-card)',
      border: '1px solid var(--shield-border)',
      padding: '1rem',
    }}>
      <div style={{
        fontFamily: 'var(--shield-font-accent)',
        fontSize: '0.6rem',
        textTransform: 'uppercase',
        letterSpacing: '2px',
        color: 'var(--shield-muted-fg)',
        marginBottom: '0.35rem',
      }}>
        {label}
      </div>
      <div style={{
        fontFamily: 'var(--shield-font-heading)',
        fontWeight: 800,
        fontSize: '1.5rem',
        color,
        lineHeight: 1,
      }}>
        {value}
      </div>
    </div>
  )
}

function ResultCard({ result }: { result: TestResult }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      style={{
        background: result.blocked ? 'rgba(255, 51, 102, 0.05)' : 'rgba(0, 255, 136, 0.03)',
        border: `1px solid ${result.blocked ? 'rgba(255, 51, 102, 0.2)' : 'rgba(0, 255, 136, 0.1)'}`,
        padding: '0.75rem',
        cursor: 'pointer',
        transition: 'all 150ms',
        animation: 'slide-in 200ms ease-out',
      }}
      onClick={() => setExpanded(!expanded)}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{
            fontFamily: 'var(--shield-font-accent)',
            fontSize: '0.6rem',
            textTransform: 'uppercase',
            letterSpacing: '1.5px',
            padding: '0.15rem 0.5rem',
            border: '1px solid',
            borderColor: result.blocked ? 'rgba(255, 51, 102, 0.4)' : 'rgba(0, 255, 136, 0.4)',
            background: result.blocked ? 'rgba(255, 51, 102, 0.1)' : 'rgba(0, 255, 136, 0.1)',
            color: result.blocked ? 'var(--shield-destructive)' : 'var(--shield-accent)',
          }}>
            {result.blocked ? 'BLOCKED' : result.status === 0 ? 'ERROR' : 'PASSED'}
          </span>
          {result.category && (
            <span style={{
              fontFamily: 'var(--shield-font-accent)',
              fontSize: '0.55rem',
              textTransform: 'uppercase',
              letterSpacing: '1px',
              color: CATEGORY_COLORS[result.category] || 'var(--shield-muted-fg)',
            }}>
              {result.category}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {result.confidence !== undefined && (
            <span style={{
              fontFamily: 'var(--shield-font-body)',
              fontSize: '0.65rem',
              color: result.confidence >= 0.9 ? 'var(--shield-destructive)' : result.confidence >= 0.7 ? 'var(--shield-warning)' : 'var(--shield-accent)',
            }}>
              {(result.confidence * 100).toFixed(0)}%
            </span>
          )}
          <span style={{
            fontFamily: 'var(--shield-font-body)',
            fontSize: '0.6rem',
            color: 'var(--shield-muted-fg)',
          }}>
            {result.responseTimeMs.toFixed(0)}ms
          </span>
          <span style={{
            fontFamily: 'var(--shield-font-body)',
            fontSize: '0.55rem',
            color: 'var(--shield-muted-fg)',
          }}>
            {result.timestamp}
          </span>
        </div>
      </div>

      <div style={{
        fontFamily: 'var(--shield-font-body)',
        fontSize: '0.7rem',
        color: 'var(--shield-fg)',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: expanded ? 'normal' : 'nowrap',
        wordBreak: expanded ? 'break-all' : undefined,
      }}>
        {result.payload}
      </div>

      {expanded && (
        <div style={{
          marginTop: '0.5rem',
          paddingTop: '0.5rem',
          borderTop: '1px solid var(--shield-border)',
          fontSize: '0.65rem',
          color: 'var(--shield-muted-fg)',
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '0.25rem',
        }}>
          <div>Target: <span style={{ color: 'var(--shield-fg)' }}>{result.method} {TARGET_INFO[result.target as TargetEndpoint]?.path}</span></div>
          <div>Status: <span style={{ color: 'var(--shield-fg)' }}>{result.status}</span></div>
          {result.matchedPayload && <div>Matched: <span style={{ color: 'var(--shield-fg)' }}>{result.matchedPayload}</span></div>}
          {result.inputField && <div>Field: <span style={{ color: 'var(--shield-fg)' }}>{result.inputField}</span></div>}
          {result.scanTimeMs !== undefined && <div>Scan: <span style={{ color: 'var(--shield-fg)' }}>{result.scanTimeMs.toFixed(2)}ms</span></div>}
          {result.strikes !== undefined && <div>Strikes: <span style={{ color: 'var(--shield-warning)' }}>{result.strikes}/3</span></div>}
          {result.encodedPayload && (
            <div style={{ gridColumn: '1 / -1' }}>
              Encoded: <span style={{ color: 'var(--shield-accent-tertiary)', wordBreak: 'break-all' }}>{result.encodedPayload.substring(0, 200)}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
