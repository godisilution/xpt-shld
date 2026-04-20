'use client'

import { ShieldDashboard } from 'xpecto-shield/dashboard'
import './shield.css'

export default function DashboardPage() {
  return <ShieldDashboard apiBase="/api/shield" />
}
