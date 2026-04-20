'use client'

import { ShieldDashboard } from './components/ShieldDashboard'
import './shield.css'

export default function DashboardPage() {
  return <ShieldDashboard apiBase="/api/shield" />
}
