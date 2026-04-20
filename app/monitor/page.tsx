'use client'

import { useState, useEffect, useCallback } from 'react'
import { CATEGORY_LABELS, CATEGORY_COLORS } from '@/lib/payloads'

interface Incident {
  id?: string
  timestamp: string
  sourceIP: string
  requestPath: string
  requestMethod: string
  attackCategory: string
  matchedPayload: string
  confidence: number
  rawInput: string
  action: string
  userAgent: string
}

interface IncidentStats {
  totalIncidents: number
  totalBlockedIPs: number
  activeThreats: number
  categoryBreakdown: Record<string, number>
  averageConfidence: number
}

export default function MonitorPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [stats, setStats] = useState<IncidentStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [categoryFilter, setCategoryFilter] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)

  const fetchData = useCallback(async () => {
    try {
      const params = new URLSearchParams({ page: '1', limit: '50' })
      if (categoryFilter) params.set('category', categoryFilter)

      const [incRes, statsRes] = await Promise.all([
        fetch(`/api/shield/incidents?${params}`),
        fetch('/api/shield/stats'),
      ])

      if (incRes.ok) {
        const data = await incRes.json()
        setIncidents(data.data || [])
      }
      if (statsRes.ok) {
        setStats(await statsRes.json())
      }
    } catch {
      console.log('[monitor] Appwrite not configured or not reachable')
    } finally {
      setLoading(false)
    }
  }, [categoryFilter])

  useEffect(() => {
    fetchData()
    if (!autoRefresh) return
    const interval = setInterval(fetchData, 3000)
    return () => clearInterval(interval)
  }, [fetchData, autoRefresh])

  const topCategory = stats?.categoryBreakdown
    ? Object.entries(stats.categoryBreakdown).sort(([, a], [, b]) => b - a)[0]
    : null

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
          Live Monitor
        </h1>
        <p style={{
          fontFamily: 'var(--shield-font-accent)',
          fontSize: '0.75rem',
          color: 'var(--shield-muted-fg)',
          textTransform: 'uppercase',
          letterSpacing: '2px',
          marginTop: '0.25rem',
        }}>
          Real-Time Attack Feed // Auto-Refresh {autoRefresh ? 'ON' : 'OFF'}
        </p>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        <MonitorStat label="Total Incidents" value={stats?.totalIncidents ?? 0} color="var(--shield-accent)" />
        <MonitorStat label="Blocked IPs" value={stats?.totalBlockedIPs ?? 0} color="var(--shield-destructive)" />
        <MonitorStat label="Active Threats (24h)" value={stats?.activeThreats ?? 0} color="var(--shield-warning)" />
        <MonitorStat
          label="Top Category"
          value={topCategory ? (CATEGORY_LABELS[topCategory[0]] || topCategory[0]) : 'N/A'}
          color="var(--shield-accent-tertiary)"
          isText
        />
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', alignItems: 'center' }}>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          style={{
            padding: '0.5rem 0.75rem',
            background: 'var(--shield-input)',
            border: '1px solid var(--shield-border)',
            color: 'var(--shield-fg)',
            fontFamily: 'var(--shield-font-body)',
            fontSize: '0.75rem',
            cursor: 'pointer',
            width: '180px',
          }}
        >
          <option value="">All Categories</option>
          {Object.entries(CATEGORY_LABELS).map(([key, label]) => (
            <option key={key} value={key}>{label}</option>
          ))}
        </select>

        <button
          onClick={() => setAutoRefresh(!autoRefresh)}
          style={{
            fontFamily: 'var(--shield-font-accent)',
            fontSize: '0.65rem',
            textTransform: 'uppercase',
            letterSpacing: '1.5px',
            padding: '0.5rem 1rem',
            border: `1px solid ${autoRefresh ? 'var(--shield-accent)' : 'var(--shield-border)'}`,
            background: autoRefresh ? 'rgba(0, 255, 136, 0.1)' : 'transparent',
            color: autoRefresh ? 'var(--shield-accent)' : 'var(--shield-muted-fg)',
            cursor: 'pointer',
          }}
        >
          {autoRefresh ? 'Auto-Refresh ON' : 'Auto-Refresh OFF'}
        </button>

        <button
          onClick={fetchData}
          style={{
            fontFamily: 'var(--shield-font-accent)',
            fontSize: '0.65rem',
            textTransform: 'uppercase',
            letterSpacing: '1.5px',
            padding: '0.5rem 1rem',
            border: 'none',
            background: 'transparent',
            color: 'var(--shield-muted-fg)',
            cursor: 'pointer',
          }}
        >
          Refresh Now
        </button>
      </div>

      {/* Incident Feed */}
      <div style={{
        background: 'var(--shield-card)',
        border: '1px solid var(--shield-border)',
      }}>
        {loading ? (
          <div style={{
            padding: '3rem',
            textAlign: 'center',
            color: 'var(--shield-muted-fg)',
            fontFamily: 'var(--shield-font-accent)',
            fontSize: '0.7rem',
            textTransform: 'uppercase',
            letterSpacing: '2px',
          }}>
            Loading...
          </div>
        ) : incidents.length === 0 ? (
          <div style={{
            padding: '3rem',
            textAlign: 'center',
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
              {categoryFilter ? 'No incidents for this category' : 'No incidents recorded yet — run some attacks from the Simulator'}
            </div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
              <thead>
                <tr>
                  {['Timestamp', 'Source IP', 'Category', 'Path', 'Payload', 'Confidence', 'Action'].map(h => (
                    <th key={h} style={{
                      fontFamily: 'var(--shield-font-accent)',
                      fontSize: '0.6rem',
                      textTransform: 'uppercase',
                      letterSpacing: '2px',
                      color: 'var(--shield-muted-fg)',
                      background: 'var(--shield-muted)',
                      padding: '0.75rem 1rem',
                      textAlign: 'left',
                      borderBottom: '1px solid var(--shield-border)',
                      whiteSpace: 'nowrap',
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc, i) => (
                  <tr key={inc.id || i} style={{ transition: 'background 150ms' }}>
                    <td style={{
                      padding: '0.6rem 1rem',
                      borderBottom: '1px solid rgba(42, 42, 58, 0.5)',
                      whiteSpace: 'nowrap',
                      color: 'var(--shield-muted-fg)',
                      fontSize: '0.7rem',
                    }}>
                      {formatTimestamp(inc.timestamp)}
                    </td>
                    <td style={{
                      padding: '0.6rem 1rem',
                      borderBottom: '1px solid rgba(42, 42, 58, 0.5)',
                      color: 'var(--shield-accent)',
                      fontFamily: 'var(--shield-font-body)',
                    }}>
                      {inc.sourceIP}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', borderBottom: '1px solid rgba(42, 42, 58, 0.5)' }}>
                      <span style={{
                        fontFamily: 'var(--shield-font-accent)',
                        fontSize: '0.55rem',
                        textTransform: 'uppercase',
                        letterSpacing: '1.5px',
                        padding: '0.15rem 0.5rem',
                        border: `1px solid ${(CATEGORY_COLORS[inc.attackCategory] || '#666')}40`,
                        background: `${CATEGORY_COLORS[inc.attackCategory] || '#666'}10`,
                        color: CATEGORY_COLORS[inc.attackCategory] || '#666',
                      }}>
                        {CATEGORY_LABELS[inc.attackCategory] || inc.attackCategory}
                      </span>
                    </td>
                    <td style={{
                      padding: '0.6rem 1rem',
                      borderBottom: '1px solid rgba(42, 42, 58, 0.5)',
                      maxWidth: '150px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>
                      {inc.requestPath}
                    </td>
                    <td style={{
                      padding: '0.6rem 1rem',
                      borderBottom: '1px solid rgba(42, 42, 58, 0.5)',
                      maxWidth: '200px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      fontSize: '0.7rem',
                      color: 'var(--shield-muted-fg)',
                    }}>
                      {inc.matchedPayload}
                    </td>
                    <td style={{ padding: '0.6rem 1rem', borderBottom: '1px solid rgba(42, 42, 58, 0.5)' }}>
                      <ConfidenceBar value={inc.confidence} />
                    </td>
                    <td style={{ padding: '0.6rem 1rem', borderBottom: '1px solid rgba(42, 42, 58, 0.5)' }}>
                      <span style={{
                        fontFamily: 'var(--shield-font-accent)',
                        fontSize: '0.55rem',
                        textTransform: 'uppercase',
                        letterSpacing: '1.5px',
                        padding: '0.15rem 0.5rem',
                        border: '1px solid rgba(255, 51, 102, 0.4)',
                        background: 'rgba(255, 51, 102, 0.1)',
                        color: 'var(--shield-destructive)',
                      }}>
                        {inc.action}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function MonitorStat({ label, value, color, isText }: { label: string; value: number | string; color: string; isText?: boolean }) {
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
        fontSize: isText ? '0.75rem' : '1.5rem',
        color,
        lineHeight: 1,
        letterSpacing: isText ? '1px' : undefined,
      }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  )
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = value * 100
  const color = pct >= 90 ? 'var(--shield-destructive)'
    : pct >= 70 ? 'var(--shield-warning)'
    : 'var(--shield-accent)'

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
      <div style={{
        width: '50px',
        height: '4px',
        background: 'var(--shield-muted)',
        overflow: 'hidden',
      }}>
        <div style={{
          width: `${pct}%`,
          height: '100%',
          background: color,
        }} />
      </div>
      <span style={{
        fontSize: '0.65rem',
        color,
        fontFamily: 'var(--shield-font-body)',
      }}>
        {pct.toFixed(0)}%
      </span>
    </div>
  )
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return iso
  }
}
