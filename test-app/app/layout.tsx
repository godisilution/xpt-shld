import type { Metadata } from 'next'
import './globals.css'
import { NavBar } from './nav-bar'

export const metadata: Metadata = {
  title: 'Xpecto Shield — Test App',
  description: 'IDPS Testing Environment for Xpecto Shield',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
          <NavBar />
          <main style={{ flex: 1, padding: '2rem', maxWidth: '1400px', width: '100%', margin: '0 auto' }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  )
}
