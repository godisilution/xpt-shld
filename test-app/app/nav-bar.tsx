'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState, useEffect } from 'react'

interface EngineStatsData {
  totalPatterns: number
  isReady: boolean
  categoryCounts: Record<string, number>
}

export function NavBar() {
  const pathname = usePathname()
  const [stats, setStats] = useState<EngineStatsData | null>(null)

  useEffect(() => {
    fetch('/api/test/engine-stats')
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data) setStats(data) })
      .catch(() => {})
  }, [])

  const links = [
    { href: '/', label: 'Simulator' },
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/monitor', label: 'Monitor' },
  ]

  return (
    <header style={{
      background: 'var(--shield-card)',
      borderBottom: '1px solid var(--shield-border)',
      padding: '0 2rem',
      position: 'sticky',
      top: 0,
      zIndex: 100,
    }}>
      <div style={{
        maxWidth: '1400px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: '56px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
          <div style={{
            fontFamily: 'var(--shield-font-heading)',
            fontWeight: 900,
            fontSize: '0.85rem',
            color: 'var(--shield-accent)',
            textTransform: 'uppercase',
            letterSpacing: '3px',
            textShadow: '0 0 10px rgba(0, 255, 136, 0.5)',
          }}>
            XPECTO SHIELD
          </div>

          <nav style={{ display: 'flex', gap: '0.25rem' }}>
            {links.map(link => {
              const isActive = link.href === '/' ? pathname === '/' : pathname.startsWith(link.href)
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  style={{
                    fontFamily: 'var(--shield-font-accent)',
                    fontSize: '0.7rem',
                    textTransform: 'uppercase',
                    letterSpacing: '1.5px',
                    padding: '0.5rem 1rem',
                    color: isActive ? 'var(--shield-accent)' : 'var(--shield-muted-fg)',
                    textDecoration: 'none',
                    borderBottom: isActive ? '2px solid var(--shield-accent)' : '2px solid transparent',
                    transition: 'all 150ms',
                  }}
                >
                  {link.label}
                </Link>
              )
            })}
          </nav>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          {stats && (
            <div style={{
              fontFamily: 'var(--shield-font-accent)',
              fontSize: '0.6rem',
              textTransform: 'uppercase',
              letterSpacing: '1.5px',
              color: 'var(--shield-muted-fg)',
            }}>
              {stats.totalPatterns.toLocaleString()} patterns loaded
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: stats?.isReady ? 'var(--shield-accent)' : 'var(--shield-muted-fg)',
              boxShadow: stats?.isReady ? '0 0 6px var(--shield-accent)' : 'none',
              display: 'inline-block',
              animation: stats?.isReady ? 'pulse-glow 2s ease-in-out infinite' : 'none',
            }} />
            <span style={{
              fontFamily: 'var(--shield-font-accent)',
              fontSize: '0.6rem',
              textTransform: 'uppercase',
              letterSpacing: '1.5px',
              color: stats?.isReady ? 'var(--shield-accent)' : 'var(--shield-muted-fg)',
            }}>
              {stats?.isReady ? 'Engine Active' : 'Loading...'}
            </span>
          </div>
        </div>
      </div>
    </header>
  )
}
