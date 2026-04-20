'use client'

import React, { useState, useEffect, useCallback } from 'react'
import type {
  IncidentStats,
  IncidentLog,
  BlockedIP,
  AIReport,
  ThreatCategory,
  PaginatedResult,
  IncidentFilters,
} from '../../core/types'
import { CATEGORY_LABELS } from '../../core/types'

// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Dashboard Root Component
// ═══════════════════════════════════════════════════════════════

export interface ShieldDashboardProps {
  /** Base URL for the Shield API (e.g., '/api/shield') */
  apiBase?: string
}

type Page = 'overview' | 'incidents' | 'blocked-ips' | 'reports' | 'settings'

const NAV_ITEMS: Array<{ id: Page; label: string; icon: string }> = [
  { id: 'overview', label: 'Overview', icon: '📊' },
  { id: 'incidents', label: 'Incidents', icon: '⚡' },
  { id: 'blocked-ips', label: 'Blocked IPs', icon: '🚫' },
  { id: 'reports', label: 'AI Reports', icon: '🤖' },
  { id: 'settings', label: 'Settings', icon: '⚙️' },
]

export function ShieldDashboard({ apiBase = '/api/shield' }: ShieldDashboardProps) {
  const [activePage, setActivePage] = useState<Page>('overview')
  const [stats, setStats] = useState<IncidentStats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/stats`)
      if (res.ok) {
        setStats(await res.json())
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err)
    } finally {
      setLoading(false)
    }
  }, [apiBase])

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [fetchStats])

  return (
    <div className="shield-dashboard">
      <div className="shield-layout">
        {/* Sidebar */}
        <aside className="shield-sidebar">
          <div className="shield-sidebar-header">
            <div className="shield-sidebar-logo">
              <span className="logo-icon">🛡️</span>
              <span className="shield-glitch" data-text="XPECTO">XPECTO</span>
            </div>
            <div className="shield-sidebar-version">Shield v0.1.0 // IDPS</div>
          </div>

          <nav className="shield-sidebar-nav">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                className={`shield-nav-item ${activePage === item.id ? 'active' : ''}`}
                onClick={() => setActivePage(item.id)}
              >
                <span className="nav-icon">{item.icon}</span>
                {item.label}
              </button>
            ))}
          </nav>

          <div className="shield-sidebar-footer">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span className="shield-status-dot shield-status-dot--active" />
              <span style={{
                fontFamily: 'var(--shield-font-accent)',
                fontSize: '0.6rem',
                textTransform: 'uppercase' as const,
                letterSpacing: '1.5px',
                color: 'var(--shield-accent)',
              }}>
                Engine Active
              </span>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="shield-main">
          {activePage === 'overview' && (
            <OverviewPage stats={stats} loading={loading} apiBase={apiBase} />
          )}
          {activePage === 'incidents' && (
            <IncidentsPage apiBase={apiBase} />
          )}
          {activePage === 'blocked-ips' && (
            <BlockedIPsPage apiBase={apiBase} />
          )}
          {activePage === 'reports' && (
            <ReportsPage apiBase={apiBase} />
          )}
          {activePage === 'settings' && (
            <SettingsPage apiBase={apiBase} />
          )}
        </main>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Overview Page
// ═══════════════════════════════════════════════════════════════

function OverviewPage({
  stats,
  loading,
  apiBase,
}: {
  stats: IncidentStats | null
  loading: boolean
  apiBase: string
}) {
  if (loading) return <LoadingState />
  if (!stats) return <EmptyState text="No data available" icon="📭" />

  const categoryColors: Record<ThreatCategory, string> = {
    sqli: '#ff3366',
    xss: '#ff00ff',
    lfi: '#00d4ff',
    ssrf: '#ffaa00',
    'path-traversal': '#9966ff',
  }

  const maxCategoryCount = Math.max(
    ...(Object.values(stats.categoryBreakdown) as number[]),
    1
  )

  return (
    <>
      <div className="shield-page-header">
        <h1 className="shield-page-title">
          <span className="shield-glitch" data-text="DASHBOARD">DASHBOARD</span>
        </h1>
        <p className="shield-page-subtitle">
          System Overview // Real-Time Threat Intelligence
        </p>
      </div>

      {/* Stat Cards */}
      <div className="shield-stats-grid">
        <div className="shield-stat-card">
          <div className="shield-stat-label">Total Incidents</div>
          <div className="shield-stat-value">{formatNumber(stats.totalIncidents)}</div>
        </div>
        <div className="shield-stat-card">
          <div className="shield-stat-label">Blocked IPs</div>
          <div className="shield-stat-value shield-stat-value--danger">
            {formatNumber(stats.totalBlockedIPs)}
          </div>
        </div>
        <div className="shield-stat-card">
          <div className="shield-stat-label">Active Threats</div>
          <div className={`shield-stat-value ${stats.activeThreats > 0 ? 'shield-stat-value--warning' : ''}`}>
            {stats.activeThreats}
          </div>
        </div>
        <div className="shield-stat-card">
          <div className="shield-stat-label">Avg Confidence</div>
          <div className="shield-stat-value shield-stat-value--tertiary">
            {(stats.averageConfidence * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem', marginBottom: '2rem' }}>
        {/* Timeline Chart */}
        <div className="shield-chart">
          <div className="shield-chart-title">Attack Timeline (24h)</div>
          <div className="shield-bar-chart">
            {stats.hourlyTimeline.length > 0 ? (
              stats.hourlyTimeline.map((point: { hour: string; count: number }, i: number) => {
                const maxCount = Math.max(...stats.hourlyTimeline.map((p: { hour: string; count: number }) => p.count), 1)
                const height = (point.count / maxCount) * 100
                return (
                  <div
                    key={i}
                    className="shield-bar"
                    style={{ height: `${Math.max(height, 2)}%` }}
                    title={`${point.hour}: ${point.count} attacks`}
                  />
                )
              })
            ) : (
              <EmptyState text="No timeline data" icon="📈" />
            )}
          </div>
        </div>

        {/* Category Breakdown */}
        <div className="shield-chart">
          <div className="shield-chart-title">Attack Categories</div>
          <div className="shield-category-bars">
            {(Object.entries(stats.categoryBreakdown) as [ThreatCategory, number][]).map(([cat, count]) => (
              <div key={cat} className="shield-category-bar">
                <div className="shield-category-bar-label">
                  {CATEGORY_LABELS[cat]?.split(' ')[0] || cat}
                </div>
                <div className="shield-category-bar-track">
                  <div
                    className="shield-category-bar-fill"
                    style={{
                      width: `${(count / maxCategoryCount) * 100}%`,
                      background: categoryColors[cat] || '#00ff88',
                    }}
                  />
                </div>
                <div className="shield-category-bar-count">{count}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Attackers */}
      {stats.topAttackerIPs.length > 0 && (
        <div className="shield-chart">
          <div className="shield-chart-title">Top Attacker IPs</div>
          <div className="shield-table-wrapper" style={{ clipPath: 'none' }}>
            <table className="shield-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Attacks</th>
                  <th>Last Category</th>
                </tr>
              </thead>
              <tbody>
                {stats.topAttackerIPs.map((attacker: { ip: string; count: number; lastCategory: ThreatCategory }, i: number) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--shield-font-body)', color: 'var(--shield-accent)' }}>
                      {attacker.ip}
                    </td>
                    <td>{attacker.count}</td>
                    <td>
                      <CategoryBadge category={attacker.lastCategory} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  )
}

// ═══════════════════════════════════════════════════════════════
// Incidents Page
// ═══════════════════════════════════════════════════════════════

function IncidentsPage({ apiBase }: { apiBase: string }) {
  const [incidents, setIncidents] = useState<PaginatedResult<IncidentLog> | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [categoryFilter, setCategoryFilter] = useState<string>('')

  const fetchIncidents = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), limit: '20' })
      if (categoryFilter) params.set('category', categoryFilter)

      const res = await fetch(`${apiBase}/incidents?${params}`)
      if (res.ok) setIncidents(await res.json())
    } catch (err) {
      console.error('Failed to fetch incidents:', err)
    } finally {
      setLoading(false)
    }
  }, [apiBase, page, categoryFilter])

  useEffect(() => { fetchIncidents() }, [fetchIncidents])

  return (
    <>
      <div className="shield-page-header">
        <h1 className="shield-page-title">Incidents</h1>
        <p className="shield-page-subtitle">Detection Log // All Intercepted Threats</p>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', alignItems: 'center' }}>
        <select
          className="shield-select"
          style={{ width: '200px' }}
          value={categoryFilter}
          onChange={(e) => { setCategoryFilter(e.target.value); setPage(1) }}
        >
          <option value="">All Categories</option>
          <option value="sqli">SQL Injection</option>
          <option value="xss">XSS</option>
          <option value="lfi">LFI</option>
          <option value="ssrf">SSRF</option>
          <option value="path-traversal">Path Traversal</option>
        </select>
        <button className="shield-btn shield-btn--ghost" onClick={() => fetchIncidents()}>
          ↻ Refresh
        </button>
      </div>

      {loading ? (
        <LoadingState />
      ) : !incidents || incidents.data.length === 0 ? (
        <EmptyState text="No incidents detected" icon="✅" />
      ) : (
        <>
          <div className="shield-table-wrapper">
            <table className="shield-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Category</th>
                  <th>Path</th>
                  <th>Confidence</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {incidents.data.map((inc: IncidentLog, i: number) => (
                  <tr key={inc.id || i}>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--shield-muted-fg)', fontSize: '0.7rem' }}>
                      {formatTimestamp(inc.timestamp)}
                    </td>
                    <td style={{ fontFamily: 'var(--shield-font-body)', color: 'var(--shield-accent)' }}>
                      {inc.sourceIP}
                    </td>
                    <td><CategoryBadge category={inc.attackCategory} /></td>
                    <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {inc.requestPath}
                    </td>
                    <td>
                      <ConfidenceBar value={inc.confidence} />
                    </td>
                    <td>
                      <span className={`shield-badge shield-badge--${inc.action}`}>
                        {inc.action}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="shield-pagination">
            <div className="shield-pagination-info">
              Page {incidents.page} of {Math.ceil(incidents.total / incidents.limit)} // {incidents.total} total
            </div>
            <div className="shield-pagination-controls">
              <button
                className="shield-btn shield-btn--ghost shield-btn--sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Prev
              </button>
              <button
                className="shield-btn shield-btn--ghost shield-btn--sm"
                disabled={!incidents.hasMore}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </button>
            </div>
          </div>
        </>
      )}
    </>
  )
}

// ═══════════════════════════════════════════════════════════════
// Blocked IPs Page
// ═══════════════════════════════════════════════════════════════

function BlockedIPsPage({ apiBase }: { apiBase: string }) {
  const [blockedIPs, setBlockedIPs] = useState<PaginatedResult<BlockedIP> | null>(null)
  const [loading, setLoading] = useState(true)
  const [blockInput, setBlockInput] = useState('')

  const fetchBlockedIPs = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch(`${apiBase}/blocked-ips`)
      if (res.ok) setBlockedIPs(await res.json())
    } catch (err) {
      console.error('Failed to fetch blocked IPs:', err)
    } finally {
      setLoading(false)
    }
  }, [apiBase])

  useEffect(() => { fetchBlockedIPs() }, [fetchBlockedIPs])

  const handleBlock = async () => {
    if (!blockInput.trim()) return
    try {
      await fetch(`${apiBase}/block-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: blockInput.trim(), duration: 86400 }),
      })
      setBlockInput('')
      fetchBlockedIPs()
    } catch (err) {
      console.error('Failed to block IP:', err)
    }
  }

  const handleUnblock = async (ip: string) => {
    try {
      await fetch(`${apiBase}/unblock-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      })
      fetchBlockedIPs()
    } catch (err) {
      console.error('Failed to unblock IP:', err)
    }
  }

  return (
    <>
      <div className="shield-page-header">
        <h1 className="shield-page-title">Blocked IPs</h1>
        <p className="shield-page-subtitle">IP Blocklist Manager // Auto & Manual Blocks</p>
      </div>

      {/* Manual Block */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <div className="shield-input-wrapper" style={{ flex: 1, maxWidth: '300px' }}>
          <span className="shield-input-prefix">&gt;</span>
          <input
            type="text"
            className="shield-input"
            placeholder="Enter IP to block..."
            value={blockInput}
            onChange={(e) => setBlockInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleBlock()}
          />
        </div>
        <button className="shield-btn shield-btn--danger" onClick={handleBlock}>
          Block IP
        </button>
      </div>

      {loading ? (
        <LoadingState />
      ) : !blockedIPs || blockedIPs.data.length === 0 ? (
        <EmptyState text="No IPs currently blocked" icon="🟢" />
      ) : (
        <div className="shield-table-wrapper">
          <table className="shield-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Strikes</th>
                <th>Blocked At</th>
                <th>Expires</th>
                <th>Last Attack</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {blockedIPs.data.map((ip: BlockedIP, i: number) => (
                <tr key={ip.id || i}>
                  <td style={{ fontFamily: 'var(--shield-font-body)', color: 'var(--shield-destructive)' }}>
                    <span className="shield-status-dot shield-status-dot--danger" />
                    {ip.ipAddress}
                  </td>
                  <td>{ip.reason}</td>
                  <td style={{ color: 'var(--shield-warning)' }}>{ip.strikeCount}</td>
                  <td style={{ fontSize: '0.7rem', color: 'var(--shield-muted-fg)' }}>
                    {formatTimestamp(ip.blockedAt)}
                  </td>
                  <td style={{ fontSize: '0.7rem', color: 'var(--shield-muted-fg)' }}>
                    {ip.expiresAt ? formatTimestamp(ip.expiresAt) : 'Permanent'}
                  </td>
                  <td><CategoryBadge category={ip.lastAttackCategory} /></td>
                  <td>
                    <button
                      className="shield-btn shield-btn--ghost shield-btn--sm"
                      onClick={() => handleUnblock(ip.ipAddress)}
                    >
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

// ═══════════════════════════════════════════════════════════════
// Reports Page
// ═══════════════════════════════════════════════════════════════

function ReportsPage({ apiBase }: { apiBase: string }) {
  const [reports, setReports] = useState<PaginatedResult<AIReport> | null>(null)
  const [selectedReport, setSelectedReport] = useState<AIReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)

  const fetchReports = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch(`${apiBase}/reports`)
      if (res.ok) setReports(await res.json())
    } catch (err) {
      console.error('Failed to fetch reports:', err)
    } finally {
      setLoading(false)
    }
  }, [apiBase])

  useEffect(() => { fetchReports() }, [fetchReports])

  const generateReport = async () => {
    setGenerating(true)
    try {
      const now = new Date()
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

      const res = await fetch(`${apiBase}/generate-report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: weekAgo.toISOString(),
          to: now.toISOString(),
        }),
      })

      if (res.ok) {
        const data = await res.json()
        setSelectedReport(data.report)
        fetchReports()
      }
    } catch (err) {
      console.error('Failed to generate report:', err)
    } finally {
      setGenerating(false)
    }
  }

  const viewReport = async (id: string) => {
    try {
      const res = await fetch(`${apiBase}/reports/${id}`)
      if (res.ok) setSelectedReport(await res.json())
    } catch (err) {
      console.error('Failed to fetch report:', err)
    }
  }

  return (
    <>
      <div className="shield-page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="shield-page-title">AI Reports</h1>
          <p className="shield-page-subtitle">AI-Powered Security Analytics</p>
        </div>
        <button
          className="shield-btn shield-btn--secondary"
          onClick={generateReport}
          disabled={generating}
        >
          {generating ? '⟳ Generating...' : '🤖 Generate Report'}
        </button>
      </div>

      {selectedReport ? (
        <div>
          <button
            className="shield-btn shield-btn--ghost"
            onClick={() => setSelectedReport(null)}
            style={{ marginBottom: '1rem' }}
          >
            ← Back to Reports
          </button>
          <ReportDetail report={selectedReport} />
        </div>
      ) : loading ? (
        <LoadingState />
      ) : !reports || reports.data.length === 0 ? (
        <EmptyState text="No reports generated yet" icon="📋" />
      ) : (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {reports.data.map((report: AIReport, i: number) => (
            <div
              key={report.id || i}
              className="shield-card shield-card--hoverable"
              style={{ cursor: 'pointer' }}
              onClick={() => report.id && viewReport(report.id)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="shield-card-title">
                    Report — {formatTimestamp(report.createdAt)}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--shield-fg)', marginBottom: '0.5rem' }}>
                    {report.executiveSummary.substring(0, 150)}...
                  </div>
                  <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.7rem', color: 'var(--shield-muted-fg)' }}>
                    <span>{report.incidentCount} incidents</span>
                    <span>Model: {report.modelUsed}</span>
                  </div>
                </div>
                <ThreatLevelBadge level={report.threatLevel} />
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

function ReportDetail({ report }: { report: AIReport }) {
  const parseJSON = (str: string) => {
    try { return JSON.parse(str) } catch { return null }
  }

  const patterns = parseJSON(report.patternAnalysis)
  const trends = parseJSON(report.trendAnalysis)
  const risks = parseJSON(report.riskAssessment)
  const recommendations = parseJSON(report.recommendations)

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      {/* Header */}
      <div className="shield-card shield-card--holographic">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div className="shield-card-title" style={{ marginBottom: 0 }}>AI Security Report</div>
          <ThreatLevelBadge level={report.threatLevel} />
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--shield-muted-fg)', display: 'flex', gap: '1.5rem' }}>
          <span>📅 {formatTimestamp(report.dateRangeStart)} → {formatTimestamp(report.dateRangeEnd)}</span>
          <span>📊 {report.incidentCount} incidents</span>
          <span>🤖 {report.modelUsed}</span>
        </div>
        <div className="shield-divider" />
        <div style={{ fontSize: '0.85rem', lineHeight: 1.7 }}>
          {report.executiveSummary}
        </div>
      </div>

      {/* Sections */}
      {patterns && (
        <div className="shield-card">
          <div className="shield-card-title">Pattern Analysis</div>
          <ReportSection data={patterns} />
        </div>
      )}
      {trends && (
        <div className="shield-card">
          <div className="shield-card-title">Trend Analysis</div>
          <ReportSection data={trends} />
        </div>
      )}
      {risks && (
        <div className="shield-card">
          <div className="shield-card-title">Risk Assessment</div>
          <ReportSection data={risks} />
        </div>
      )}
      {recommendations && (
        <div className="shield-card">
          <div className="shield-card-title">Recommendations</div>
          <ReportSection data={recommendations} />
        </div>
      )}
    </div>
  )
}

function ReportSection({ data }: { data: Record<string, unknown> }) {
  return (
    <div style={{ fontSize: '0.8rem', lineHeight: 1.7 }}>
      {Object.entries(data).map(([key, value]) => (
        <div key={key} style={{ marginBottom: '0.75rem' }}>
          <div style={{
            fontFamily: 'var(--shield-font-accent)',
            fontSize: '0.65rem',
            textTransform: 'uppercase' as const,
            letterSpacing: '1.5px',
            color: 'var(--shield-accent)',
            marginBottom: '0.25rem',
          }}>
            {key.replace(/([A-Z])/g, ' $1').trim()}
          </div>
          <div style={{ color: 'var(--shield-fg)' }}>
            {Array.isArray(value)
              ? (value as string[]).map((item, i) => (
                  <div key={i} style={{ paddingLeft: '1rem', position: 'relative' }}>
                    <span style={{ position: 'absolute', left: 0, color: 'var(--shield-accent)' }}>›</span>
                    {String(item)}
                  </div>
                ))
              : typeof value === 'object' && value !== null
                ? JSON.stringify(value, null, 2)
                : String(value)
            }
          </div>
        </div>
      ))}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Settings Page
// ═══════════════════════════════════════════════════════════════

function SettingsPage({ apiBase }: { apiBase: string }) {
  const [settings, setSettings] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [setupRunning, setSetupRunning] = useState(false)

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${apiBase}/settings`)
        if (res.ok) setSettings(await res.json())
      } catch (err) {
        console.error('Failed to fetch settings:', err)
      } finally {
        setLoading(false)
      }
    })()
  }, [apiBase])

  const saveSettings = async () => {
    setSaving(true)
    try {
      await fetch(`${apiBase}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      })
    } catch (err) {
      console.error('Failed to save settings:', err)
    } finally {
      setSaving(false)
    }
  }

  const runSetup = async () => {
    setSetupRunning(true)
    try {
      const res = await fetch(`${apiBase}/setup`, { method: 'POST' })
      const data = await res.json()
      alert(data.message || 'Setup complete!')
    } catch (err) {
      console.error('Setup failed:', err)
      alert('Setup failed. Check console for details.')
    } finally {
      setSetupRunning(false)
    }
  }

  if (loading) return <LoadingState />

  return (
    <>
      <div className="shield-page-header">
        <h1 className="shield-page-title">Settings</h1>
        <p className="shield-page-subtitle">System Configuration // Appwrite & AI</p>
      </div>

      <div style={{ display: 'grid', gap: '1rem', maxWidth: '600px' }}>
        {/* Appwrite Setup */}
        <div className="shield-card">
          <div className="shield-card-title">Database Setup</div>
          <p style={{ fontSize: '0.8rem', color: 'var(--shield-muted-fg)', marginBottom: '1rem' }}>
            Initialize or verify Appwrite collections, attributes, and indexes.
          </p>
          <button
            className="shield-btn"
            onClick={runSetup}
            disabled={setupRunning}
          >
            {setupRunning ? '⟳ Running...' : '⚡ Run Setup'}
          </button>
        </div>

        {/* Engine Settings */}
        <div className="shield-card">
          <div className="shield-card-title">Engine Settings</div>
          <div style={{ display: 'grid', gap: '1rem' }}>
            <SettingField
              label="Confidence Threshold"
              value={settings['confidenceThreshold'] || '0.7'}
              onChange={(v) => setSettings({ ...settings, confidenceThreshold: v })}
            />
            <SettingField
              label="Max Strikes"
              value={settings['maxStrikes'] || '3'}
              onChange={(v) => setSettings({ ...settings, maxStrikes: v })}
            />
            <SettingField
              label="Block Duration (seconds)"
              value={settings['blockDuration'] || '86400'}
              onChange={(v) => setSettings({ ...settings, blockDuration: v })}
            />
          </div>
        </div>

        <button
          className="shield-btn shield-btn--filled"
          onClick={saveSettings}
          disabled={saving}
          style={{ justifySelf: 'start' }}
        >
          {saving ? '⟳ Saving...' : '💾 Save Settings'}
        </button>
      </div>
    </>
  )
}

function SettingField({
  label,
  value,
  onChange,
}: {
  label: string
  value: string
  onChange: (v: string) => void
}) {
  return (
    <div>
      <label style={{
        display: 'block',
        fontFamily: 'var(--shield-font-accent)',
        fontSize: '0.65rem',
        textTransform: 'uppercase' as const,
        letterSpacing: '1.5px',
        color: 'var(--shield-muted-fg)',
        marginBottom: '0.25rem',
      }}>
        {label}
      </label>
      <div className="shield-input-wrapper">
        <span className="shield-input-prefix">&gt;</span>
        <input
          type="text"
          className="shield-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Shared Components
// ═══════════════════════════════════════════════════════════════

function CategoryBadge({ category }: { category: ThreatCategory }) {
  return (
    <span className={`shield-badge shield-badge--${category}`}>
      {CATEGORY_LABELS[category] || category}
    </span>
  )
}

function ThreatLevelBadge({ level }: { level: string }) {
  return (
    <span className={`shield-badge shield-badge--${level}`}>
      {level}
    </span>
  )
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = value * 100
  const color = pct >= 90 ? 'var(--shield-destructive)'
    : pct >= 70 ? 'var(--shield-warning)'
    : 'var(--shield-accent)'

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <div style={{
        width: '60px',
        height: '4px',
        background: 'var(--shield-muted)',
        overflow: 'hidden',
      }}>
        <div style={{
          width: `${pct}%`,
          height: '100%',
          background: color,
          transition: 'width 300ms',
        }} />
      </div>
      <span style={{ fontSize: '0.7rem', color, fontFamily: 'var(--shield-font-body)' }}>
        {pct.toFixed(0)}%
      </span>
    </div>
  )
}

function LoadingState() {
  return (
    <div className="shield-loading">
      <div className="shield-loading-dots">
        <div className="shield-loading-dot" />
        <div className="shield-loading-dot" />
        <div className="shield-loading-dot" />
      </div>
    </div>
  )
}

function EmptyState({ text, icon }: { text: string; icon: string }) {
  return (
    <div className="shield-empty">
      <div className="shield-empty-icon">{icon}</div>
      <div className="shield-empty-text">{text}</div>
    </div>
  )
}

// ─── Formatters ────────────────────────────────────────────────

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`
  return String(n)
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })
  } catch {
    return iso
  }
}
