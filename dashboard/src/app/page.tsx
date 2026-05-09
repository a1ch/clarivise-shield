'use client'
import { useEffect, useState } from 'react'
import { Shield, AlertTriangle, CheckCircle, XCircle, Inbox, Settings, List } from 'lucide-react'

type Stats = {
  total_scanned: number
  quarantine_pending: number
  threat_rate: number
  verdicts: { SAFE: number; SPAM: number; SUSPICIOUS: number; PHISHING: number }
}
type Scan = {
  id: string; created_at: string; verdict: string; phishing_score: number
  spam_score: number; sender: string; subject: string; actioned: string; summary: string
}
type QuarantineItem = {
  id: string; created_at: string; sender: string; subject: string
  verdict: string; phishing_score: number; summary: string; status: string
}

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''
const ADMIN_API    = `${SUPABASE_URL}/functions/v1/shield-admin`

async function api(path: string, token: string, method = 'GET', body?: unknown) {
  const res = await fetch(ADMIN_API + path, {
    method,
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  return res.json()
}

export default function Dashboard() {
  const [token, setToken]           = useState('')
  const [authed, setAuthed]         = useState(false)
  const [tab, setTab]               = useState<'overview'|'scans'|'quarantine'|'settings'>('overview')
  const [stats, setStats]           = useState<Stats | null>(null)
  const [scans, setScans]           = useState<Scan[]>([])
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([])
  const [loading, setLoading]       = useState(false)

  async function login() {
    setLoading(true)
    const data = await api('/stats', token)
    if (data.total_scanned !== undefined) { setAuthed(true); setStats(data) }
    else alert('Invalid credentials')
    setLoading(false)
  }

  async function loadTab(t: typeof tab) {
    setTab(t); setLoading(true)
    if (t === 'overview') { const d = await api('/stats', token); setStats(d) }
    else if (t === 'scans') { const d = await api('/scans?limit=100', token); setScans(d.scans ?? []) }
    else if (t === 'quarantine') { const d = await api('/quarantine', token); setQuarantine(d.quarantine ?? []) }
    setLoading(false)
  }

  async function releaseEmail(id: string) {
    await api(`/quarantine/${id}/release`, token, 'POST', { notes: 'Released by admin' })
    setQuarantine(q => q.filter(e => e.id !== id))
  }
  async function deleteEmail(id: string) {
    await api(`/quarantine/${id}/delete`, token, 'POST')
    setQuarantine(q => q.filter(e => e.id !== id))
  }

  const vColor = (v: string) => ({ SAFE: 'text-green-400', SPAM: 'text-yellow-400', SUSPICIOUS: 'text-orange-400', PHISHING: 'text-red-400' }[v] ?? 'text-gray-400')
  const vBg    = (v: string) => ({ SAFE: 'bg-green-900/30 border-green-700', SPAM: 'bg-yellow-900/30 border-yellow-700', SUSPICIOUS: 'bg-orange-900/30 border-orange-700', PHISHING: 'bg-red-900/30 border-red-700' }[v] ?? 'bg-gray-800 border-gray-600')

  if (!authed) return (
    <div className="min-h-screen flex items-center justify-center bg-[#0f1f33]">
      <div className="bg-[#1a3050] rounded-2xl p-10 w-full max-w-sm shadow-2xl border border-[#2E75B6]/30">
        <div className="flex items-center gap-3 mb-8">
          <Shield className="text-[#2E75B6]" size={32} />
          <div><h1 className="text-xl font-bold text-white">Clarivise Shield</h1><p className="text-sm text-slate-400">Admin Dashboard</p></div>
        </div>
        <label className="block text-sm text-slate-400 mb-2">Admin Email</label>
        <input className="w-full bg-[#0f1f33] border border-[#2E75B6]/40 rounded-lg px-4 py-3 text-white text-sm mb-6 focus:outline-none focus:border-[#2E75B6]" placeholder="admin@yourcompany.com" value={token} onChange={e => setToken(e.target.value)} onKeyDown={e => e.key === 'Enter' && login()} />
        <button onClick={login} disabled={loading} className="w-full bg-[#2E75B6] hover:bg-[#1F4E79] text-white font-semibold py-3 rounded-lg transition-colors disabled:opacity-50">{loading ? 'Signing in...' : 'Sign In'}</button>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-[#0f1f33] flex">
      <aside className="w-56 bg-[#1a3050] border-r border-[#2E75B6]/20 flex flex-col py-6 px-4 flex-shrink-0">
        <div className="flex items-center gap-2 mb-8 px-2"><Shield className="text-[#2E75B6]" size={22} /><span className="font-bold text-white text-sm">Clarivise Shield</span></div>
        {[
          { id: 'overview',   label: 'Overview',   icon: <CheckCircle size={16} /> },
          { id: 'scans',      label: 'Scan Log',   icon: <List size={16} /> },
          { id: 'quarantine', label: 'Quarantine', icon: <Inbox size={16} /> },
          { id: 'settings',   label: 'Settings',   icon: <Settings size={16} /> },
        ].map(item => (
          <button key={item.id} onClick={() => loadTab(item.id as typeof tab)}
            className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium mb-1 transition-colors ${tab === item.id ? 'bg-[#2E75B6] text-white' : 'text-slate-400 hover:text-white hover:bg-[#2E75B6]/20'}`}>
            {item.icon} {item.label}
            {item.id === 'quarantine' && stats && stats.quarantine_pending > 0 && (
              <span className="ml-auto bg-red-500 text-white text-xs font-bold rounded-full px-1.5 py-0.5">{stats.quarantine_pending}</span>
            )}
          </button>
        ))}
      </aside>

      <main className="flex-1 p-8 overflow-auto">
        {tab === 'overview' && stats && (
          <div>
            <h2 className="text-2xl font-bold text-white mb-6">Overview - Last 30 Days</h2>
            <div className="grid grid-cols-4 gap-4 mb-8">
              {[
                { label: 'Emails Scanned',     value: stats.total_scanned,     icon: <CheckCircle size={20} />,   color: 'text-blue-400' },
                { label: 'Quarantine Pending', value: stats.quarantine_pending, icon: <Inbox size={20} />,         color: 'text-red-400' },
                { label: 'Threat Rate',        value: `${stats.threat_rate}%`, icon: <AlertTriangle size={20} />, color: 'text-orange-400' },
                { label: 'Phishing Caught',    value: stats.verdicts.PHISHING, icon: <XCircle size={20} />,       color: 'text-red-400' },
              ].map(card => (
                <div key={card.label} className="bg-[#1a3050] rounded-xl p-5 border border-[#2E75B6]/20">
                  <div className={`${card.color} mb-2`}>{card.icon}</div>
                  <div className="text-3xl font-bold text-white mb-1">{card.value}</div>
                  <div className="text-xs text-slate-400">{card.label}</div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-4 gap-4">
              {Object.entries(stats.verdicts).map(([verdict, count]) => (
                <div key={verdict} className={`rounded-xl p-4 border ${vBg(verdict)}`}>
                  <div className={`text-lg font-bold ${vColor(verdict)}`}>{verdict}</div>
                  <div className="text-2xl font-bold text-white">{count}</div>
                  <div className="text-xs text-slate-400">{stats.total_scanned ? Math.round((count / stats.total_scanned) * 100) : 0}% of total</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'scans' && (
          <div>
            <h2 className="text-2xl font-bold text-white mb-6">Scan Log</h2>
            <div className="space-y-2">
              {scans.map(scan => (
                <div key={scan.id} className={`rounded-lg p-4 border ${vBg(scan.verdict)} flex items-start gap-4`}>
                  <span className={`font-bold text-sm w-24 flex-shrink-0 ${vColor(scan.verdict)}`}>{scan.verdict}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-white truncate">{scan.subject}</div>
                    <div className="text-xs text-slate-400 mt-0.5">{scan.sender}</div>
                    <div className="text-xs text-slate-500 mt-1">{scan.summary}</div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div className="text-xs text-slate-400">{new Date(scan.created_at).toLocaleString()}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{scan.actioned}</div>
                  </div>
                </div>
              ))}
              {scans.length === 0 && !loading && <p className="text-slate-500 text-sm">No scans yet.</p>}
            </div>
          </div>
        )}

        {tab === 'quarantine' && (
          <div>
            <h2 className="text-2xl font-bold text-white mb-6">Quarantine Queue</h2>
            <div className="space-y-3">
              {quarantine.map(item => (
                <div key={item.id} className="bg-[#1a3050] rounded-xl p-5 border border-red-800/40">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-red-400 font-bold text-sm">{item.verdict}</span>
                        <span className="text-xs text-slate-500">{new Date(item.created_at).toLocaleString()}</span>
                      </div>
                      <div className="text-sm font-semibold text-white truncate">{item.subject}</div>
                      <div className="text-xs text-slate-400">{item.sender}</div>
                      <div className="text-xs text-slate-500 mt-2">{item.summary}</div>
                    </div>
                    <div className="flex gap-2 flex-shrink-0">
                      <button onClick={() => releaseEmail(item.id)} className="px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs font-semibold rounded-lg transition-colors">Release</button>
                      <button onClick={() => deleteEmail(item.id)} className="px-3 py-1.5 bg-red-800 hover:bg-red-700 text-white text-xs font-semibold rounded-lg transition-colors">Delete</button>
                    </div>
                  </div>
                </div>
              ))}
              {quarantine.length === 0 && !loading && <p className="text-slate-500 text-sm">Quarantine is empty.</p>}
            </div>
          </div>
        )}

        {loading && <div className="flex items-center justify-center py-20"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#2E75B6]"></div></div>}
      </main>
    </div>
  )
}
