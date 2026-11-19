import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { BrowserRouter, Link, NavLink, Navigate, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import { api, formatApiError, parseParamsSchema, unlockViewToken } from './api'
import type { AuditEntry, Provider, VPS, Website } from './api'
import { getLocale, setLocale, t, type Locale } from './i18n'
import { AlertRulesPage, ChangeSnapshots, CheckupPanel, DisablePasswordButton, ExpectationsPanel, HostOps, MaintenanceWindowsEditor, MetricsHistory, SFTPBrowser, ScanDiff, ScriptDetailPage, TaskDetailPage, TemplatesPage, VPSPicker, WebSSH, decideTask } from './ops'
import './index.css'

const qc = new QueryClient()

// Warm CSRF cookie on load (server-panel pattern)
fetch('/api/setup/status', { credentials: 'include' }).catch(() => {})

function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => api<{ username: string; vault: string; must_change_password: boolean; totp_enabled: boolean }>('/api/me'),
    retry: false,
  })
}

function Shell({ children }: { children: React.ReactNode }) {
  const me = useMe()
  const nav = useNavigate()
  const [locale, setLoc] = useState<Locale>(getLocale())
  const lock = useMutation({
    mutationFn: () => api('/api/vault/lock', { method: 'POST' }),
    onSuccess: () => me.refetch(),
  })
  const logout = useMutation({
    mutationFn: () => api('/api/logout', { method: 'POST' }),
    onSuccess: () => nav('/login'),
  })

  if (me.isError) return <Navigate to="/login" replace />
  if (me.isLoading) return <div className="auth-screen muted">{t('loading')}</div>
  if (me.data?.must_change_password) return <Navigate to="/password" replace />

  const vault = me.data?.vault ?? 'locked'
  const switchLang = () => {
    const next: Locale = locale === 'zh-CN' ? 'en-US' : 'zh-CN'
    setLocale(next)
    setLoc(next)
  }

  return (
    <div className="shell">
      <header className="shell-header">
        <Link to="/" className="shell-brand">{t('brand', locale)}</Link>
        <nav className="shell-nav">
          {([
            ['/', t('dashboard', locale), true],
            ['/vps', t('vps', locale), false],
            ['/providers', t('providers', locale), false],
            ['/websites', t('websites', locale), false],
            ['/matrix', t('matrix', locale), false],
            ['/templates', t('templates', locale), false],
            ['/tasks', t('tasks', locale), false],
            ['/scripts', t('scripts', locale), false],
            ['/audit', t('audit', locale), false],
            ['/alerts', t('alerts', locale), false],
            ['/alert-rules', t('alertRules', locale), false],
            ['/backups', t('backups', locale), false],
            ['/settings', t('settings', locale), false],
          ] as [string, string, boolean][]).map(([to, label, end]) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => isActive ? 'is-active' : undefined}>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="shell-actions">
          <button className="btn secondary" onClick={switchLang}>{locale === 'zh-CN' ? 'EN' : '中文'}</button>
          <span className="muted">{me.data?.username}</span>
          <span className={`badge ${vault === 'unlocked' ? 'ok' : 'warn'}`}>
            {t('vault', locale)}: {vault === 'expired' ? 'expired' : vault}
          </span>
          {vault === 'unlocked' ? (
            <button className="btn secondary" onClick={() => lock.mutate()}>{t('lock', locale)}</button>
          ) : (
            <Link className="btn secondary" to="/vault">{vault === 'expired' ? 'Re-unlock' : t('unlock', locale)}</Link>
          )}
          <button className="btn secondary" onClick={() => logout.mutate()}>{t('logout', locale)}</button>
        </div>
      </header>
      {vault !== 'unlocked' && (
        <div className="banner">
          <span>{t('vaultBanner', locale)}</span>
          <Link className="btn secondary" to="/vault">{t('unlockVault', locale)}</Link>
        </div>
      )}
      {me.data?.totp_enabled === false && (
        <div className="banner">
          <span>{t('totpBanner', locale)}</span>
          <Link className="btn secondary" to="/settings">{t('enrollTotp', locale)}</Link>
        </div>
      )}
      <main className="shell-main">{children}</main>
    </div>
  )
}

function DashboardPage() {
  const [days, setDays] = useState(30)
  const [kindFilter, setKindFilter] = useState<'all' | 'vps' | 'website'>('all')
  const dash = useQuery({
    queryKey: ['dashboard', days],
    queryFn: () => api<{
      stats: {
        total_vps: number; online_count: number; offline_count: number
        expiring_count: number; overdue_count: number; total_websites: number
        vps_expiring_count?: number; website_expiring_count?: number
        vps_overdue_count?: number; website_overdue_count?: number
        recent_alerts: number; probe_unhealthy: number; total_providers: number
        waiting_approval?: number
        host_key_pending_count?: number
        stale_scan_count?: number
      }
      expiring: { id: number; kind: string; name: string; expiry_date: string; days_left: number; detail?: string }[]
      days: number
    }>(`/api/dashboard?days=${days}`),
  })
  const s = dash.data?.stats
  const rows = (dash.data?.expiring ?? []).filter((e) => kindFilter === 'all' || e.kind === kindFilter)
  const fleetStats: [string, number | undefined, string | null][] = [
    [t('vps'), s?.total_vps, '/vps'],
    [t('online'), s?.online_count, '/vps?status=online'],
    [t('offline'), s?.offline_count, '/vps?status=offline'],
    [t('websites'), s?.total_websites, '/websites'],
    [t('providers'), s?.total_providers, '/providers'],
  ]
  const attentionStats: [string, number | undefined, string | null][] = [
    [t('expiringVPS'), s?.vps_expiring_count ?? s?.expiring_count, '/vps?filter=expiring'],
    [t('overdueVPS'), s?.vps_overdue_count ?? s?.overdue_count, '/vps?filter=overdue'],
    [t('expiringSites'), s?.website_expiring_count, '/websites?filter=expiring'],
    [t('overdueSites'), s?.website_overdue_count, '/websites?filter=overdue'],
    [t('alerts'), s?.recent_alerts, '/alerts?open=1'],
    [t('probeUnhealthy'), s?.probe_unhealthy, '/websites?filter=probe_fail'],
    [t('waitingApproval'), s?.waiting_approval, '/tasks?status=waiting_approval'],
    [t('hostKeyPending'), s?.host_key_pending_count, '/vps?filter=host_key_pending'],
    [t('staleScan'), s?.stale_scan_count, '/vps?filter=stale_scan'],
  ]
  const renderStat = ([label, val, href]: [string, number | undefined, string | null]) => {
    const n = Number(val ?? 0)
    const quiet = !n
    return (
      <div className={`card stat-card${quiet ? ' is-quiet' : ''}`} key={String(label)}>
        <div className="stat-label">{label}</div>
        <div className="stat-value">
          {href && n > 0 ? <Link to={href}>{n}</Link> : (val ?? '—')}
        </div>
      </div>
    )
  }
  return (
    <Shell>
      <h2 className="text-xl mb-3">{t('dashboard')}</h2>
      <p className="stat-section-label">{t('fleet')}</p>
      <div className="stat-grid">{fleetStats.map(renderStat)}</div>
      <p className="stat-section-label">{t('attention')}</p>
      <div className="stat-grid mb-4">{attentionStats.map(renderStat)}</div>
      <div className="card">
        <div className="flex flex-wrap gap-2 items-end mb-2">
          <h3 className="flex-1">{t('expiring')}</h3>
          <div className="field !mb-0"><label>{t('withinDays')}</label>
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {[7, 14, 30, 60, 90].map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </div>
          <div className="field !mb-0"><label>{t('kind')}</label>
            <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value as typeof kindFilter)}>
              <option value="all">{t('filterAll')}</option>
              <option value="vps">{t('vps')}</option>
              <option value="website">{t('websites')}</option>
            </select>
          </div>
        </div>
        {rows.length ? (
          <table className="table">
            <thead><tr><th>{t('kind')}</th><th>{t('name')}</th><th>{t('date')}</th><th>{t('days')}</th></tr></thead>
            <tbody>
              {rows.map((e) => (
                <tr key={`${e.kind}-${e.id}`}>
                  <td>{e.kind}</td>
                  <td>
                    {e.kind === 'vps' ? <Link to={`/vps/${e.id}`}>{e.name}</Link> : e.kind === 'website' ? <Link to={`/websites?highlight=${e.id}`}>{e.name}</Link> : e.name}
                    {e.detail ? ` (${e.detail})` : ''}
                  </td>
                  <td>{e.expiry_date}</td>
                  <td className={e.days_left < 0 ? 'error' : ''}>{e.days_left}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted text-sm">{t('emptyList')}</p>
        )}
      </div>
    </Shell>
  )
}

function ProvidersPage() {
  const list = useQuery({ queryKey: ['providers'], queryFn: () => api<Provider[]>('/api/providers') })
  const [name, setName] = useState('')
  const [website, setWebsite] = useState('')
  const [contact, setContact] = useState('')
  const [privateNotes, setPrivateNotes] = useState('')
  const [msg, setMsg] = useState('')
  const create = async () => {
    await api('/api/providers', {
      method: 'POST',
      body: JSON.stringify({ name, website, contact, private_notes: privateNotes || undefined }),
    })
    setName(''); setWebsite(''); setContact(''); setPrivateNotes(''); list.refetch()
  }
  const reveal = async (id: number) => {
    try {
      const token = await unlockViewToken()
      const notes = await api<{ private_notes: string }>(`/api/providers/${id}/reveal-notes`, {
        method: 'POST', headers: { 'X-View-Token': token },
      })
      setMsg(notes.private_notes || '(empty)')
    } catch (ex) {
      const msg = formatApiError(ex)
      setMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
    }
  }
  const putProvider = async (p: Provider, patch: Partial<Provider> & { private_notes?: string }) => {
    await api(`/api/providers/${p.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        name: patch.name ?? p.name,
        website: patch.website ?? p.website ?? '',
        contact: patch.contact ?? p.contact ?? '',
        notes: patch.notes ?? p.notes ?? '',
        private_notes: patch.private_notes,
      }),
    })
    list.refetch()
  }
  return (
    <Shell>
      <h2 className="text-xl mb-3">{t('providers')}</h2>
      <div className="card mb-4">
        <h3 className="form-section-title">{t('newProvider')}</h3>
        <div className="grid md:grid-cols-2 gap-2 items-end">
          <div className="field !mb-0"><label>{t('name')}</label><input value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="field !mb-0"><label>{t('website')}</label><input value={website} onChange={(e) => setWebsite(e.target.value)} /></div>
          <div className="field !mb-0"><label>{t('contact')}</label><input value={contact} onChange={(e) => setContact(e.target.value)} /></div>
          <div className="field !mb-0"><label>{t('privateNotes')}</label><input value={privateNotes} onChange={(e) => setPrivateNotes(e.target.value)} placeholder="encrypted at rest" /></div>
        </div>
        <div className="settings-actions">
          <button className="btn" onClick={create}>{t('create')}</button>
        </div>
      </div>
      {msg && <p className="muted mb-2 text-sm break-all">{msg}</p>}
      <p className="stat-section-label">{t('catalog')}</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>{t('name')}</th><th>{t('website')}</th><th>{t('contact')}</th><th>{t('servers')}</th><th></th></tr></thead>
          <tbody>
            {(list.data ?? []).map((p) => (
              <tr key={p.id}>
                <td>
                  {p.name}
                  {p.has_private_notes ? <span className="badge warn ml-1">private</span> : null}
                  {p.notes ? <div className="muted text-xs truncate max-w-[12rem]">{p.notes}</div> : null}
                </td>
                <td className="muted text-sm">{p.website || '—'}</td>
                <td className="muted text-sm">{p.contact || '—'}</td>
                <td className="font-variant-numeric tabular-nums">
                  {(p.server_count ?? 0) > 0
                    ? <Link to={`/vps?provider_id=${p.id}`}>{p.server_count}</Link>
                    : <span className="muted">0</span>}
                </td>
                <td className="flex flex-wrap gap-1">
                  {p.has_private_notes && <button className="btn secondary" onClick={() => reveal(p.id)}>{t('reveal')}</button>}
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Name', p.name)
                    if (next == null || !next.trim()) return
                    await putProvider(p, { name: next.trim() })
                  }}>Name</button>
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Website URL', p.website || '')
                    if (next == null) return
                    await putProvider(p, { website: next })
                  }}>Site</button>
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Contact', p.contact || '')
                    if (next == null) return
                    await putProvider(p, { contact: next })
                  }}>Contact</button>
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Public notes', p.notes || '')
                    if (next == null) return
                    await putProvider(p, { notes: next })
                  }}>Notes</button>
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Private notes (vault; blank keeps existing)')
                    if (!next) return
                    try { await putProvider(p, { private_notes: next }) }
                    catch (ex) { setMsg((ex as Error).message) }
                  }}>Private notes</button>
                  <button className="btn secondary" onClick={async () => {
                    if (!confirm(`Delete provider ${p.name}?`)) return
                    await api(`/api/providers/${p.id}`, { method: 'DELETE' })
                    list.refetch()
                  }}>{t('delete')}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!list.isLoading && !(list.data ?? []).length && <p className="muted text-sm p-3">{t('emptyProviders')}</p>}
      </div>
    </Shell>
  )
}

function WebsitesPage() {
  const list = useQuery({ queryKey: ['websites'], queryFn: () => api<Website[]>('/api/websites') })
  const vps = useQuery({ queryKey: ['vps'], queryFn: () => api<VPS[]>('/api/vps') })
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [vpsId, setVpsId] = useState<number | ''>('')
  const [expiry, setExpiry] = useState('')
  const [siteType, setSiteType] = useState('other')
  const [status, setStatus] = useState('active')
  const [panelType, setPanelType] = useState('none')
  const [panelURL, setPanelURL] = useState('')
  const [panelUser, setPanelUser] = useState('')
  const initialFilter = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('filter') || '' : ''
  const [filter, setFilter] = useState(initialFilter)
  const highlight = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('highlight') : null
  const create = async () => {
    await api('/api/websites', {
      method: 'POST',
      body: JSON.stringify({
        name, domain, vps_id: vpsId || null, site_type: siteType || 'other', status: status || 'active',
        panel_type: panelType || 'none', panel_url: panelURL || '', panel_username: panelUser || '',
        http_probe_enabled: true, expiry_date: expiry || null,
      }),
    })
    setName(''); setDomain(''); setExpiry(''); setPanelURL(''); setPanelUser(''); list.refetch()
  }
  const rows = (list.data ?? []).filter((w) => {
    if (filter === 'probe_fail') return w.http_probe_enabled && !w.http_probe_healthy
    if (filter === 'expiring') {
      if (!w.expiry_date) return false
      const left = (new Date(w.expiry_date).getTime() - Date.now()) / 86400000
      return left >= 0 && left < 30
    }
    if (filter === 'overdue') {
      if (!w.expiry_date) return false
      return (new Date(w.expiry_date).getTime() - Date.now()) < 0
    }
    if (filter === 'no_vps') return !w.vps_id
    return true
  })
  useEffect(() => {
    if (!highlight) return
    const el = document.getElementById(`website-${highlight}`)
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [highlight, list.data])
  const siteStatusBadge = (st?: string) => {
    if (st === 'active') return 'ok'
    if (st === 'paused') return 'warn'
    if (st === 'archived') return 'err'
    return ''
  }
  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('websites')}</h2>
        <select className="field" style={{ width: 160 }} value={filter} onChange={(e) => {
          const v = e.target.value
          setFilter(v)
          const sp = new URLSearchParams(window.location.search)
          if (v) sp.set('filter', v); else sp.delete('filter')
          const qstr = sp.toString()
          window.history.replaceState(null, '', qstr ? `/websites?${qstr}` : '/websites')
        }}>
          <option value="">{t('filterAll')}</option>
          <option value="probe_fail">{t('probeFail')}</option>
          <option value="expiring">{t('expiringSoon')}</option>
          <option value="overdue">{t('overdue')}</option>
          <option value="no_vps">{t('noVps')}</option>
        </select>
      </div>
      <div className="card mb-4">
        <h3 className="form-section-title">{t('newWebsite')}</h3>
        <div className="grid md:grid-cols-4 gap-2 items-end">
          <div className="field !mb-0"><label>{t('name')}</label><input value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="field !mb-0"><label>{t('domain')}</label><input value={domain} onChange={(e) => setDomain(e.target.value)} /></div>
          <div className="field !mb-0"><label>{t('vps')}</label>
            <select value={vpsId} onChange={(e) => setVpsId(e.target.value ? Number(e.target.value) : '')}>
              <option value="">—</option>
              {(vps.data ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
          </div>
          <div className="field !mb-0"><label>{t('expiry')}</label><input type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} /></div>
          <div className="field !mb-0"><label>{t('type')}</label>
            <select value={siteType} onChange={(e) => setSiteType(e.target.value)}>
              <option value="other">other</option>
              <option value="blog">blog</option>
              <option value="shop">shop</option>
              <option value="panel">panel</option>
              <option value="api">api</option>
            </select>
          </div>
          <div className="field !mb-0"><label>{t('status')}</label>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="active">active</option>
              <option value="paused">paused</option>
              <option value="archived">archived</option>
            </select>
          </div>
          <div className="field !mb-0"><label>Panel type</label><input value={panelType} onChange={(e) => setPanelType(e.target.value)} /></div>
          <div className="field !mb-0"><label>Panel URL</label><input value={panelURL} onChange={(e) => setPanelURL(e.target.value)} /></div>
          <div className="field !mb-0"><label>Panel user</label><input value={panelUser} onChange={(e) => setPanelUser(e.target.value)} /></div>
        </div>
        <div className="settings-actions">
          <button className="btn" onClick={create}>{t('create')}</button>
        </div>
      </div>
      <p className="stat-section-label">{t('catalog')}</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>{t('name')}</th><th>{t('domain')}</th><th>{t('type')}</th><th>{t('vps')}</th><th>{t('probe')}</th><th>{t('when')}</th><th>{t('expiry')}</th><th></th></tr></thead>
          <tbody>
            {rows.map((w) => (
              <tr key={w.id} id={`website-${w.id}`} className={highlight === String(w.id) ? 'row-highlight' : undefined}>
                <td>{w.name}<div className="mt-0.5"><span className={`badge ${siteStatusBadge(w.status)}`}>{w.status}</span></div></td>
                <td>
                  {w.domain}
                  {w.panel_url ? <div className="muted text-xs truncate max-w-[10rem]">{w.panel_url}</div> : null}
                  {w.panel_username ? <div className="muted text-xs">user: {w.panel_username}</div> : null}
                </td>
                <td className="muted text-xs">{w.site_type}{w.panel_type && w.panel_type !== 'none' ? ` · ${w.panel_type}` : ''}</td>
                <td className="muted">{w.vps_id ? <Link to={`/vps/${w.vps_id}`}>{w.vps_name || w.vps_id}</Link> : '—'}</td>
                <td>
                  <span className={`badge ${w.http_probe_healthy ? 'ok' : w.http_probe_enabled ? 'err' : ''}`}>
                    {w.http_probe_enabled ? (w.http_probe_healthy ? 'ok' : 'fail') : 'off'}
                  </span>
                  {w.http_probe_url && <div className="muted text-xs mt-0.5 truncate max-w-[12rem]" title={w.http_probe_url}>{w.http_probe_url}</div>}
                </td>
                <td className="text-xs muted max-w-[14rem]">
                  {w.http_probe_last_at ? new Date(w.http_probe_last_at).toLocaleString() : '—'}
                  {w.http_probe_last_error && <div className="error truncate" title={w.http_probe_last_error}>{w.http_probe_last_error}</div>}
                </td>
                <td>{w.expiry_date || '—'}</td>
                <td className="flex flex-wrap gap-1">
                  <button className="btn secondary" onClick={async () => {
                    await api(`/api/websites/${w.id}`, {
                      method: 'PUT',
                      body: JSON.stringify({
                        ...w,
                        http_probe_enabled: !w.http_probe_enabled,
                      }),
                    })
                    list.refetch()
                  }}>{w.http_probe_enabled ? 'Probe off' : 'Probe on'}</button>
                  <button className="btn secondary" onClick={async () => {
                    const url = prompt('Probe URL (blank = https://domain)', w.http_probe_url || '')
                    if (url == null) return
                    await api(`/api/websites/${w.id}`, {
                      method: 'PUT',
                      body: JSON.stringify({ ...w, http_probe_url: url }),
                    })
                    list.refetch()
                  }}>Probe URL</button>
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Expiry YYYY-MM-DD', w.expiry_date || '')
                    if (next == null) return
                    await api(`/api/websites/${w.id}`, {
                      method: 'PUT',
                      body: JSON.stringify({ ...w, expiry_date: next || null }),
                    })
                    list.refetch()
                  }}>Expiry</button>
                  <button className="btn secondary" onClick={async () => {
                    const next = prompt('Panel username', w.panel_username || '')
                    if (next == null) return
                    await api(`/api/websites/${w.id}`, {
                      method: 'PUT',
                      body: JSON.stringify({ ...w, panel_username: next }),
                    })
                    list.refetch()
                  }}>Panel user</button>
                  <button className="btn secondary" onClick={async () => {
                    const pw = prompt('Panel password to store (encrypted)')
                    if (!pw) return
                    try {
                      await api(`/api/websites/${w.id}/password`, { method: 'POST', body: JSON.stringify({ password: pw }) })
                      list.refetch()
                    } catch (ex) { alert((ex as Error).message) }
                  }}>Set panel pw</button>
                  <button className="btn secondary" onClick={async () => {
                    try {
                      const token = await unlockViewToken()
                      const r = await api<{ password: string }>(`/api/websites/${w.id}/reveal`, {
                        method: 'POST', headers: { 'X-View-Token': token },
                      })
                      alert(r.password || '(empty)')
                    } catch (ex) {
                      const msg = formatApiError(ex)
                      alert(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
                    }
                  }}>Reveal pw</button>
                  <button className="btn secondary" onClick={async () => {
                    if (!confirm(`Delete website ${w.name}?`)) return
                    await api(`/api/websites/${w.id}`, { method: 'DELETE' })
                    list.refetch()
                  }}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!list.isLoading && rows.length === 0 && <p className="muted text-sm p-3">{t('emptyWebsites')}</p>}
      </div>
    </Shell>
  )
}

function SetupPage() {
  const nav = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [totpUrl, setTotpUrl] = useState('')
  const [err, setErr] = useState('')
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      const res = await api<{ totp_url: string }>('/api/setup', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })
      setTotpUrl(res.totp_url)
    } catch (ex) {
      setErr((ex as Error).message)
    }
  }
  return (
    <div className="auth-screen">
      <div className="card auth-card">
        <h1>{t('brand')}</h1>
        <p className="muted mb-4">Create the admin account. TOTP is mandatory.</p>
        {!totpUrl ? (
          <form onSubmit={submit}>
            <div className="field"><label>{t('username')}</label><input value={username} onChange={(e) => setUsername(e.target.value)} /></div>
            <div className="field"><label>{t('password')}</label><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={8} /></div>
            {err && <p className="error">{err}</p>}
            <button className="btn" type="submit">Create admin</button>
          </form>
        ) : (
          <div>
            <p className="mb-2">Scan this TOTP URL in your authenticator, then login:</p>
            <code className="text-xs break-all block mb-4">{totpUrl}</code>
            <button className="btn" onClick={() => nav('/login')}>{t('login')}</button>
          </div>
        )}
      </div>
    </div>
  )
}

function LoginPage() {
  const nav = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [totpUrl, setTotpUrl] = useState('')
  const [err, setErr] = useState('')
  const status = useQuery({
    queryKey: ['setup'],
    queryFn: () => api<{ needs_setup: boolean }>('/api/setup/status'),
  })
  if (status.data?.needs_setup) return <Navigate to="/setup" replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      const res = await api<{ must_change_password?: boolean }>('/api/login', { method: 'POST', body: JSON.stringify({ username, password, totp }) })
      nav(res.must_change_password ? '/password' : '/')
    } catch (ex) {
      const e2 = ex as Error & { data?: { totp_url?: string; error?: string } }
      if (e2.data?.totp_url) setTotpUrl(e2.data.totp_url)
      setErr(e2.message)
    }
  }
  return (
    <div className="auth-screen">
      <div className="card auth-card">
        <h1>{t('brand')}</h1>
        <p className="muted mb-4">{t('signIn')} — {t('password')} + {t('totp')}</p>
        <form onSubmit={submit}>
          <div className="field"><label>{t('username')}</label><input value={username} onChange={(e) => setUsername(e.target.value)} /></div>
          <div className="field"><label>{t('password')}</label><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
          <div className="field"><label>{t('totp')}</label><input value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="6-digit code" /></div>
          {totpUrl && <code className="text-xs break-all block mb-3">{totpUrl}</code>}
          {err && (
            <p className="error mb-2">
              {err === 'vault_locked' ? t('vaultLockedHint') : err}
              {(err.toLowerCase().includes('lock') || err.toLowerCase().includes('too many') || err.toLowerCase().includes('rate')) && (
                <> · <Link to="/settings#locks">{t('locks')}</Link></>
              )}
            </p>
          )}
          <button className="btn" type="submit">{t('login')}</button>
        </form>
      </div>
    </div>
  )
}

function PasswordPage() {
  const nav = useNavigate()
  const q = useQueryClient()
  const [oldP, setOldP] = useState('')
  const [newP, setNewP] = useState('')
  const [err, setErr] = useState('')
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      await api('/api/password', { method: 'POST', body: JSON.stringify({ old_password: oldP, new_password: newP }) })
      await q.invalidateQueries({ queryKey: ['me'] })
      nav('/')
    } catch (ex) { setErr((ex as Error).message) }
  }
  return (
    <div className="auth-screen">
      <div className="card auth-card">
        <h1>{t('changePassword')}</h1>
        <p className="muted text-sm mb-4">{t('changePasswordHint')}</p>
        <form onSubmit={submit}>
          <div className="field"><label>{t('currentPassword')}</label><input type="password" value={oldP} onChange={(e) => setOldP(e.target.value)} /></div>
          <div className="field"><label>{t('newPassword')}</label><input type="password" value={newP} onChange={(e) => setNewP(e.target.value)} minLength={8} /></div>
          {err && <p className="error mb-2">{err}</p>}
          <button className="btn" type="submit">{t('save')}</button>
        </form>
      </div>
    </div>
  )
}

function VaultPage() {
  const nav = useNavigate()
  const q = useQueryClient()
  const status = useQuery({
    queryKey: ['vault'],
    queryFn: () => api<{ state: string; initialized: boolean; recovery_ready?: boolean }>('/api/vault/status'),
  })
  const [pw, setPw] = useState('')
  const [recovery, setRecovery] = useState('')
  const [recKey, setRecKey] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [mode, setMode] = useState<'unlock' | 'recover'>('unlock')
  const [err, setErr] = useState('')

  const init = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      const res = await api<{ recovery_key: string }>('/api/vault/init', {
        method: 'POST', body: JSON.stringify({ master_password: pw }),
      })
      setRecovery(res.recovery_key)
      q.invalidateQueries({ queryKey: ['me'] })
      status.refetch()
    } catch (ex) { setErr((ex as Error).message) }
  }
  const unlock = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      await api('/api/vault/unlock', { method: 'POST', body: JSON.stringify({ master_password: pw }) })
      q.invalidateQueries({ queryKey: ['me'] })
      nav('/')
    } catch (ex) { setErr((ex as Error).message) }
  }
  const recover = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    if (newPw !== confirmPw) { setErr('password confirmation mismatch'); return }
    try {
      const res = await api<{ recovery_key: string }>('/api/vault/recover', {
        method: 'POST',
        body: JSON.stringify({ recovery_key: recKey, new_password: newPw, confirm_password: confirmPw }),
      })
      setRecovery(res.recovery_key)
      q.invalidateQueries({ queryKey: ['me'] })
      setMode('unlock')
      setRecKey(''); setNewPw(''); setConfirmPw('')
    } catch (ex) { setErr((ex as Error).message) }
  }

  const vaultState = status.data?.state ?? (status.data?.initialized ? 'locked' : 'uninitialized')
  const vaultBadge = vaultState === 'unlocked' ? 'ok' : vaultState === 'expired' ? 'err' : 'warn'
  return (
    <Shell>
      <div className="card max-w-lg">
        <h2 className="text-xl mb-2">{t('vaultTitle')}</h2>
        <div className="vault-state">
          <span className={`badge ${vaultBadge}`}>{vaultState}</span>
          {status.data?.recovery_ready ? <span className="badge ok">recovery ready</span> : status.data?.initialized ? <span className="badge warn">recovery pending</span> : null}
        </div>
        <p className="muted text-sm mb-4">
          Credentials stay encrypted at rest. Panel restarts locked.
          {status.data?.state === 'expired' && ' Auto-lock TTL expired — unlock again.'}
        </p>
        {!status.data?.initialized ? (
          <form onSubmit={init}>
            <div className="field"><label>New master password (min 12)</label>
              <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={12} /></div>
            {err && <p className="error mb-2">{err}</p>}
            {recovery && (
              <p className="mb-3 text-sm border border-[var(--border)] rounded-[var(--radius)] p-3 bg-[var(--panel-soft)]">
                {t('recoveryKeyOffline')}: <code className="break-all">{recovery}</code>
              </p>
            )}
            <button className="btn" type="submit">{t('vaultInit')}</button>
          </form>
        ) : mode === 'unlock' ? (
          <>
            <form onSubmit={unlock}>
              <div className="field"><label>Master password</label>
                <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></div>
              {err && <p className="error mb-2">{err}</p>}
              {recovery && (
                <p className="mb-3 text-sm border border-[var(--border)] rounded-[var(--radius)] p-3 bg-[var(--panel-soft)]">
                  {t('recoveryKeyOffline')}: <code className="break-all">{recovery}</code>
                </p>
              )}
              <button className="btn" type="submit">{t('unlock')}</button>
            </form>
            <button className="btn secondary mt-3" type="button" onClick={() => { setMode('recover'); setErr(''); setRecovery('') }}>
              {t('vaultRecover')}
            </button>
          </>
        ) : (
          <form onSubmit={recover}>
            <p className="muted text-sm mb-3">
              Use the offline recovery key to set a new master password.
              {!status.data?.recovery_ready && ' (Rotate once while unlocked if recovery was never wrapped.)'}
            </p>
            <div className="field"><label>Recovery key</label>
              <input value={recKey} onChange={(e) => setRecKey(e.target.value)} autoComplete="off" /></div>
            <div className="field"><label>New master password (min 12)</label>
              <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} minLength={12} /></div>
            <div className="field"><label>Confirm new password</label>
              <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} minLength={12} /></div>
            {err && <p className="error mb-2">{err}</p>}
            {recovery && (
              <p className="mb-3 text-sm border border-[var(--border)] rounded-[var(--radius)] p-3 bg-[var(--panel-soft)]">
                {t('recoveryKeyOffline')}: <code className="break-all">{recovery}</code>
              </p>
            )}
            <div className="settings-actions">
              <button className="btn" type="submit">{t('vaultRecover')}</button>
              <button className="btn secondary" type="button" onClick={() => { setMode('unlock'); setErr('') }}>{t('cancel')}</button>
            </div>
          </form>
        )}
      </div>
    </Shell>
  )
}

function MaintenanceStatusBadge({ id }: { id: string }) {
  const st = useQuery({
    queryKey: ['maint', id],
    queryFn: () => api<{ unrestricted: boolean; in_window: boolean; weekday: number; now: string }>(`/api/vps/${id}/maintenance-status`),
    refetchInterval: 60_000,
  })
  if (!st.data) return null
  if (st.data.unrestricted) {
    return <p className="muted text-xs mt-1">{t('maintUnrestricted')}</p>
  }
  return (
    <p className={`text-xs mt-1 ${st.data.in_window ? 'ok' : 'warn'}`}>
      {st.data.in_window ? t('maintInside') : t('maintOutside')} (weekday {st.data.weekday})
    </p>
  )
}

function VPSList() {
  const nav = useNavigate()
  const initialStatus = new URLSearchParams(window.location.search).get('status') || ''
  const initialExpiry = new URLSearchParams(window.location.search).get('filter') || ''
  const initialProvider = new URLSearchParams(window.location.search).get('provider_id') || ''
  const [q, setQ] = useState('')
  const [environment, setEnvironment] = useState('')
  const [status, setStatus] = useState(initialStatus)
  const [expiryFilter, setExpiryFilter] = useState(initialExpiry)
  const [hostKeyFilter, setHostKeyFilter] = useState(initialExpiry === 'host_key_pending')
  const [staleScanFilter, setStaleScanFilter] = useState(initialExpiry === 'stale_scan')
  const [probeFailFilter, setProbeFailFilter] = useState(initialExpiry === 'probe_fail')
  const [providerID, setProviderID] = useState(initialProvider)
  const [group, setGroup] = useState('')
  const [tag, setTag] = useState('')
  const [picked, setPicked] = useState<number[]>([])
  const [mode, setMode] = useState('normal_tasks')
  const [batchProvider, setBatchProvider] = useState('')
  const [fleetScript, setFleetScript] = useState('security-baseline')
  const [msg, setMsg] = useState('')
  const [testResults, setTestResults] = useState<{
    id: number; name: string; ok: boolean; error?: string; host_key_pending?: string
  }[] | null>(null)
  const [showTrash, setShowTrash] = useState(false)
  const providers = useQuery({ queryKey: ['providers'], queryFn: () => api<Provider[]>('/api/providers') })
  const qs = new URLSearchParams()
  if (q) qs.set('q', q)
  if (environment) qs.set('environment', environment)
  if (status) qs.set('status', status)
  if (group) qs.set('group', group)
  if (tag) qs.set('tag', tag)
  if (providerID) qs.set('provider_id', providerID)
  const list = useQuery({
    queryKey: ['vps', q, environment, status, group, tag, providerID],
    queryFn: () => api<VPS[]>(`/api/vps?${qs.toString()}`),
  })
  const trash = useQuery({
    queryKey: ['vps-deleted'],
    queryFn: () => api<(VPS & { deleted_at?: string })[]>('/api/vps/deleted'),
    enabled: showTrash,
  })
  const isStaleScan = (v: VPS) => {
    if (!v.last_scan_at) return true
    return (Date.now() - new Date(v.last_scan_at).getTime()) > 7 * 86400000
  }
  const rows = (list.data ?? []).filter((v) => {
    if (hostKeyFilter || expiryFilter === 'host_key_pending') return !!v.host_key_pending
    if (staleScanFilter || expiryFilter === 'stale_scan') return isStaleScan(v)
    if (probeFailFilter || expiryFilter === 'probe_fail') return !!v.http_probe_enabled && !v.http_probe_healthy
    if (!expiryFilter) return true
    if (!v.expires_at) return false
    const left = (new Date(v.expires_at).getTime() - Date.now()) / 86400000
    if (expiryFilter === 'overdue') return left < 0
    if (expiryFilter === 'expiring') return left >= 0 && left < 30
    return true
  })
  const relTime = (iso?: string) => {
    if (!iso) return t('neverScanned')
    const ms = Date.now() - new Date(iso).getTime()
    const d = Math.floor(ms / 86400000)
    if (d >= 1) return `${d}d`
    const h = Math.floor(ms / 3600000)
    if (h >= 1) return `${h}h`
    const m = Math.max(1, Math.floor(ms / 60000))
    return `${m}m`
  }
  const toggle = (id: number) => setPicked((cur) => cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id])
  const apply = async (fields: Record<string, string | number>) => {
    setMsg('')
    setTestResults(null)
    try {
      await api('/api/vps/batch', { method: 'POST', body: JSON.stringify({ ids: picked, fields }) })
      setMsg(`Updated ${picked.length}`)
      list.refetch()
    } catch (ex) {
      const msg = formatApiError(ex)
      setMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
    }
  }
  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('vps')}</h2>
        <input className="field" style={{ width: 180 }} placeholder={t('search')} value={q} onChange={(e) => setQ(e.target.value)} />
        <input className="field" style={{ width: 120 }} placeholder={t('group')} value={group} onChange={(e) => setGroup(e.target.value)} />
        <input className="field" style={{ width: 100 }} placeholder={t('tag')} value={tag} onChange={(e) => setTag(e.target.value)} />
        <select className="field" style={{ width: 140 }} value={environment} onChange={(e) => setEnvironment(e.target.value)}>
          <option value="">{t('allEnv')}</option>
          <option value="production">production</option>
          <option value="testing">testing</option>
        </select>
        <select className="field" style={{ width: 140 }} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">{t('allStatus')}</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="unknown">unknown</option>
        </select>
        <select className="field" style={{ width: 160 }} value={hostKeyFilter ? 'host_key_pending' : staleScanFilter ? 'stale_scan' : probeFailFilter ? 'probe_fail' : expiryFilter} onChange={(e) => {
          const v = e.target.value
          const pending = v === 'host_key_pending'
          const stale = v === 'stale_scan'
          const probe = v === 'probe_fail'
          setHostKeyFilter(pending)
          setStaleScanFilter(stale)
          setProbeFailFilter(probe)
          setExpiryFilter(pending || stale || probe ? '' : v)
          const sp = new URLSearchParams(window.location.search)
          if (v) sp.set('filter', v); else sp.delete('filter')
          const qstr = sp.toString()
          window.history.replaceState(null, '', qstr ? `/vps?${qstr}` : '/vps')
        }}>
          <option value="">{t('filterAll')}</option>
          <option value="expiring">{t('expiringSoon')}</option>
          <option value="overdue">{t('overdue')}</option>
          <option value="host_key_pending">{t('hostKeyPending')}</option>
          <option value="stale_scan">{t('staleScan')}</option>
          <option value="probe_fail">{t('probeFail')}</option>
        </select>
        <select className="field" style={{ width: 160 }} value={providerID} onChange={(e) => {
          const v = e.target.value
          setProviderID(v)
          const sp = new URLSearchParams(window.location.search)
          if (v) sp.set('provider_id', v); else sp.delete('provider_id')
          const qstr = sp.toString()
          window.history.replaceState(null, '', qstr ? `/vps?${qstr}` : '/vps')
        }}>
          <option value="">{t('providers')}</option>
          {(providers.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <Link className="btn" to="/vps/new">{t('addVPS')}</Link>
        <label className="btn secondary">
          {t('import')}
          <input className="hidden" type="file" accept=".csv,text/csv" onChange={async (e) => {
            const input = e.target
            const file = input.files?.[0]
            if (!file) return
            const body = new FormData()
            body.append('file', file)
            try {
              const r = await api<{ created: number }>('/api/vps/import', { method: 'POST', body })
              setMsg(t('importedN').replace('{n}', String(r.created ?? 0)))
              list.refetch()
            } catch (ex) {
              const err = ex as Error & { code?: string }
              setMsg(err.code === 'vault_locked' || err.message === 'vault_locked'
                ? t('vaultLockedHint')
                : `${t('importFailed')}: ${err.message}`)
            } finally {
              input.value = ''
            }
          }} />
        </label>
        <button className="btn secondary" onClick={async () => {
          const res = await fetch('/api/vps/export', { credentials: 'include' })
          const blob = await res.blob()
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = 'vpshub-vps.csv'
          a.click()
          URL.revokeObjectURL(url)
        }}>{t('export')}</button>
        <button className="btn secondary" onClick={() => setShowTrash((v) => !v)}>{showTrash ? t('hideTrash') : t('trash')}</button>
      </div>
      {showTrash && (
        <div className="card mb-4">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <h3 className="text-sm flex-1">{t('trash')}</h3>
            {(trash.data ?? []).length > 0 && (
              <button className="btn secondary" onClick={async () => {
                if (!confirm(`Permanently purge all ${(trash.data ?? []).length} soft-deleted VPS? This cannot be undone.`)) return
                await api('/api/vps/purge-batch', {
                  method: 'POST',
                  body: JSON.stringify({ confirm: true, all: true }),
                })
                trash.refetch()
                setMsg('Trash emptied')
              }}>{t('emptyTrash')}</button>
            )}
          </div>
          {(trash.data ?? []).length === 0 && <p className="muted text-sm">Empty</p>}
          <table className="table">
            <tbody>
              {(trash.data ?? []).map((v) => (
                <tr key={v.id}>
                  <td>{v.name}</td>
                  <td className="muted">{v.host}</td>
                  <td className="muted text-xs">{v.deleted_at ? new Date(v.deleted_at).toLocaleString() : ''}</td>
                  <td className="flex gap-2">
                    <button className="btn secondary" onClick={async () => {
                      await api(`/api/vps/${v.id}/restore`, { method: 'POST' })
                      trash.refetch()
                      list.refetch()
                    }}>{t('restoreVPS')}</button>
                    <button className="btn secondary" onClick={async () => {
                      if (!confirm(`Permanently delete ${v.name}? This cannot be undone.`)) return
                      await api(`/api/vps/${v.id}/purge`, { method: 'POST', body: JSON.stringify({ confirm: true }) })
                      trash.refetch()
                    }}>{t('purge')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {picked.length > 0 && (
        <div className="card mb-4 flex flex-wrap gap-2 items-end">
          <span className="text-sm">{picked.length} selected</span>
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="readonly_monitor">readonly_monitor</option>
            <option value="normal_tasks">normal_tasks</option>
            <option value="high_risk_allowed">high_risk_allowed</option>
            <option value="no_changes">no_changes</option>
          </select>
          <button className="btn secondary" onClick={() => apply({ op_mode: mode })}>Set mode</button>
          <button className="btn secondary" onClick={() => apply({ environment: 'production' })}>Mark production</button>
          <button className="btn secondary" onClick={() => apply({ environment: 'testing' })}>Mark testing</button>
          <button className="btn secondary" onClick={() => {
            const raw = prompt('Set tags (comma-separated)', '')
            if (raw == null) return
            const tags = JSON.stringify(raw.split(',').map((s) => s.trim()).filter(Boolean))
            apply({ tags })
          }}>Set tags</button>
          <button className="btn secondary" onClick={() => {
            const g = prompt('Set group name', '')
            if (g == null) return
            apply({ group_name: g })
          }}>Set group</button>
          <button className="btn secondary" onClick={() => {
            const g = prompt('Set region', '')
            if (g == null) return
            apply({ region: g })
          }}>Set region</button>
          <select className="field !mb-0" style={{ width: 140 }} value={batchProvider} onChange={(e) => setBatchProvider(e.target.value)}>
            <option value="">Provider…</option>
            {(providers.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button className="btn secondary" disabled={!batchProvider} onClick={() => {
            const p = (providers.data ?? []).find((x) => String(x.id) === batchProvider)
            if (!p) return
            apply({ provider_id: p.id, provider: p.name })
          }}>Assign provider</button>
          <button className="btn secondary" onClick={async () => {
            setMsg(''); setTestResults(null)
            try {
              const tsk = await api<{ id: string }>('/api/vps/batch-scan', { method: 'POST', body: JSON.stringify({ ids: picked }) })
              nav(`/tasks/${tsk.id}`)
            } catch (ex) {
              const msg = formatApiError(ex)
              setMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
            }
          }}>Scan</button>
          <select className="field !mb-0" style={{ width: 180 }} value={fleetScript} onChange={(e) => setFleetScript(e.target.value)}>
            <option value="security-baseline">security-baseline</option>
            <option value="docker-prune-dry">docker-prune-dry</option>
            <option value="process-top">process-top</option>
            <option value="auth-log-tail">auth-log-tail</option>
            <option value="conn-summary">conn-summary</option>
            <option value="disk-inodes">disk-inodes</option>
            <option value="apt-autoremove-dry">apt-autoremove-dry</option>
          </select>
          <button className="btn secondary" onClick={async () => {
            setMsg(''); setTestResults(null)
            try {
              const scripts = await api<{ id: number; name: string; status: string }[]>('/api/scripts')
              const sc = (scripts ?? []).find((s) => s.name === fleetScript && (s.status === 'published' || s.status === 'approved'))
              if (!sc) { setMsg(`script "${fleetScript}" not published`); return }
              const tsk = await api<{ id: string }>('/api/tasks', {
                method: 'POST',
                body: JSON.stringify({
                  type: 'script', vps_ids: picked, dry_run: true, risk_level: 'low', confirm: false,
                  payload: { script_id: sc.id, params: {} },
                }),
              })
              nav(`/tasks/${tsk.id}`)
            } catch (ex) {
              const msg = formatApiError(ex)
              setMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
            }
          }}>{t('runPublishedScript')}</button>
          <button className="btn secondary" onClick={async () => {
            setMsg(''); setTestResults(null)
            try {
              const res = await api<{ results: {
                id: number; name: string; ok: boolean; error?: string
                host_key_pending?: string; status_updated?: string
              }[] }>('/api/vps/batch-test', { method: 'POST', body: JSON.stringify({ ids: picked }) })
              list.refetch()
              setTestResults(res.results)
              const bad = res.results.filter((r) => !r.ok)
              if (!bad.length) setMsg(`All ${res.results.length} reachable`)
              else setMsg(`${bad.length}/${res.results.length} failed`)
            } catch (ex) {
              const msg = formatApiError(ex)
              setMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
            }
          }}>Test SSH</button>
        </div>
      )}
      {msg && <p className="muted mb-3">{msg}</p>}
      {testResults && (
        <ul className="card mb-3 text-sm space-y-1">
          {testResults.map((r) => (
            <li key={r.id} className={r.ok ? 'muted' : 'error'}>
              <Link to={`/vps/${r.id}`}>{r.name}</Link>
              {': '}
              {r.ok ? 'ok' : (r.error || 'fail')}
              {r.host_key_pending ? <> · <Link to={`/vps/${r.id}`}>confirm host key</Link></> : null}
            </li>
          ))}
        </ul>
      )}
      <div className="card overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th><input type="checkbox" checked={rows.length > 0 && picked.length === rows.length} onChange={(e) => setPicked(e.target.checked ? rows.map((v) => v.id) : [])} /></th>
              <th>{t('name')}</th><th>{t('host')}</th><th>{t('group')}</th><th>{t('env')}</th><th>{t('mode')}</th><th>{t('status')}</th><th>{t('lastScan')}</th><th>{t('expiry')}</th><th>{t('probe')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((v) => {
              const expiring = v.expires_at && (new Date(v.expires_at).getTime() - Date.now()) < 14 * 86400000
              const probe = !v.http_probe_enabled ? '—' : v.http_probe_healthy ? 'ok' : 'fail'
              const stale = isStaleScan(v)
              return (
              <tr key={v.id}>
                <td><input type="checkbox" checked={picked.includes(v.id)} onChange={() => toggle(v.id)} /></td>
                <td>
                  <Link to={`/vps/${v.id}`}>{v.name}</Link>
                  {v.host_key_pending ? <> <span className="badge warn">{t('hostKeyPending')}</span></> : null}
                </td>
                <td className="muted">{v.host}:{v.ssh_port}</td>
                <td>{v.group_name}</td>
                <td>{v.environment}</td>
                <td>{v.op_mode}</td>
                <td><span className={`badge ${v.status === 'online' ? 'ok' : ''}`}>{v.status}</span></td>
                <td className={`text-xs ${stale ? 'warn' : 'muted'}`} title={v.last_scan_at || ''}>{relTime(v.last_scan_at)}</td>
                <td className={`text-xs ${expiring ? 'warn' : 'muted'}`}>
                  {v.expires_at ? new Date(v.expires_at).toLocaleDateString() : '—'}
                  {v.monthly_cost != null ? ` · ${v.currency || ''} ${v.monthly_cost}` : ''}
                </td>
                <td><span className={`badge ${probe === 'ok' ? 'ok' : probe === 'fail' ? 'err' : ''}`}>{probe}</span></td>
              </tr>
              )
            })}
          </tbody>
        </table>
        {list.isLoading && <p className="muted">{t('loading')}</p>}
        {!list.isLoading && rows.length === 0 && <p className="muted text-sm p-3">{t('emptyVPS')}</p>}
      </div>
    </Shell>
  )
}

function VPSForm({ initial }: { initial?: Partial<VPS> }) {
  const nav = useNavigate()
  const providers = useQuery({ queryKey: ['providers'], queryFn: () => api<Provider[]>('/api/providers') })
  const [form, setForm] = useState({
    name: initial?.name ?? '',
    host: initial?.host ?? '',
    ssh_port: initial?.ssh_port ?? 22,
    ssh_user: initial?.ssh_user ?? 'root',
    auth_method: initial?.auth_method ?? 'password',
    provider: initial?.provider ?? '',
    region: initial?.region ?? '',
    group_name: initial?.group_name ?? '',
    environment: initial?.environment ?? 'production',
    op_mode: initial?.op_mode ?? 'normal_tasks',
    notes: initial?.notes ?? '',
    tags: initial?.tags ?? '[]',
    maintenance_windows: initial?.maintenance_windows ?? '[]',
    server_type: initial?.server_type ?? 'vps',
    renewal_cycle: initial?.renewal_cycle ?? 'monthly',
    currency: initial?.currency ?? 'USD',
    expires_at: initial?.expires_at ?? '',
    purchase_date: initial?.purchase_date ?? '',
    http_probe_url: initial?.http_probe_url ?? '',
    bandwidth: initial?.bandwidth ?? '',
    sftp_root: initial?.sftp_root ?? '',
    socks_proxy: initial?.socks_proxy ?? '',
    jump_host_id: initial?.jump_host_id ? String(initial.jump_host_id) : '',
    provider_id: initial?.provider_id ? String(initial.provider_id) : '',
    monthly_cost: initial?.monthly_cost != null ? String(initial.monthly_cost) : '',
    purchase_price: initial?.purchase_price != null ? String(initial.purchase_price) : '',
    cpu_cores: initial?.cpu_cores != null ? String(initial.cpu_cores) : '',
    ram_gb: initial?.ram_gb != null ? String(initial.ram_gb) : '',
    disk_gb: initial?.disk_gb != null ? String(initial.disk_gb) : '',
    ipv4: initial?.ipv4 ?? '',
    ipv6: initial?.ipv6 ?? '',
    panel_type: initial?.panel_type ?? '',
    panel_url: initial?.panel_url ?? '',
    panel_username: initial?.panel_username ?? '',
  })
  const [autoRenewal, setAutoRenewal] = useState(!!initial?.auto_renewal)
  const [probeOn, setProbeOn] = useState(!!initial?.http_probe_enabled)
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [sudoPass, setSudoPass] = useState('')
  const [tagText, setTagText] = useState(() => {
    try {
      const arr = JSON.parse(initial?.tags || '[]') as string[]
      return Array.isArray(arr) ? arr.join(', ') : ''
    } catch { return '' }
  })
  const [err, setErr] = useState('')
  const set = (k: string, v: string | number) => setForm((f) => ({ ...f, [k]: v }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    try {
      const tags = JSON.stringify(tagText.split(',').map((s) => s.trim()).filter(Boolean))
      const numOrNull = (s: string) => {
        if (!s.trim()) return null
        const n = Number(s)
        return Number.isFinite(n) ? n : null
      }
      const body = {
        ...form,
        tags,
        maintenance_windows: form.maintenance_windows || '[]',
        jump_host_id: form.jump_host_id ? Number(form.jump_host_id) : null,
        provider_id: form.provider_id ? Number(form.provider_id) : null,
        expires_at: form.expires_at || null,
        purchase_date: form.purchase_date || null,
        monthly_cost: numOrNull(form.monthly_cost),
        purchase_price: numOrNull(form.purchase_price),
        cpu_cores: numOrNull(form.cpu_cores),
        ram_gb: numOrNull(form.ram_gb),
        disk_gb: numOrNull(form.disk_gb),
        auto_renewal: autoRenewal,
        http_probe_enabled: probeOn,
      }
      let id = initial?.id
      if (id) {
        await api(`/api/vps/${id}`, { method: 'PUT', body: JSON.stringify({ ...body, id }) })
      } else {
        const created = await api<VPS>('/api/vps', { method: 'POST', body: JSON.stringify(body) })
        id = created.id
      }
      if (password || privateKey || passphrase || sudoPass) {
        await api(`/api/vps/${id}/credentials`, {
          method: 'POST',
          body: JSON.stringify({
            password: password || undefined,
            private_key: privateKey || undefined,
            passphrase: passphrase || undefined,
            sudo_password: sudoPass || undefined,
          }),
        })
      }
      nav(`/vps/${id}`)
    } catch (ex) {
      setErr((ex as Error).message)
    }
  }

  return (
    <form className="card max-w-xl" onSubmit={submit}>
      <div className="field"><label>Name</label><input value={form.name} onChange={(e) => set('name', e.target.value)} required /></div>
      <div className="field"><label>Host</label><input value={form.host} onChange={(e) => set('host', e.target.value)} required /></div>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Port</label><input type="number" value={form.ssh_port} onChange={(e) => set('ssh_port', Number(e.target.value))} /></div>
        <div className="field">
          <label>User {form.ssh_user === 'root' && <span className="warn text-xs">high-risk</span>}</label>
          <input value={form.ssh_user} onChange={(e) => set('ssh_user', e.target.value)} />
          {form.ssh_user === 'root' && <p className="muted text-xs mt-1">Prefer a dedicated admin + limited sudo; root is high-risk.</p>}
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Auth method</label>
          <select value={form.auth_method} onChange={(e) => set('auth_method', e.target.value)}>
            <option value="password">password</option>
            <option value="key">key</option>
            <option value="key_password">key+password</option>
          </select>
        </div>
        <div className="field"><label>Group</label><input value={form.group_name} onChange={(e) => set('group_name', e.target.value)} /></div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Provider</label>
          <select value={form.provider_id} onChange={(e) => {
            const id = e.target.value
            set('provider_id', id)
            const p = (providers.data ?? []).find((x) => String(x.id) === id)
            if (p) set('provider', p.name)
          }}>
            <option value="">—</option>
            {(providers.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
        <div className="field"><label>Region</label><input value={form.region} onChange={(e) => set('region', e.target.value)} /></div>
      </div>
      <div className="field"><label>Tags (comma-separated)</label><input value={tagText} onChange={(e) => setTagText(e.target.value)} placeholder="prod, edge" /></div>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Environment</label>
          <select value={form.environment} onChange={(e) => set('environment', e.target.value)}>
            <option value="production">production</option>
            <option value="testing">testing</option>
          </select>
        </div>
        <div className="field"><label>Op mode</label>
          <select value={form.op_mode} onChange={(e) => set('op_mode', e.target.value)}>
            <option value="readonly_monitor">readonly_monitor — scan/probe only</option>
            <option value="normal_tasks">normal_tasks — medium risk OK</option>
            <option value="high_risk_allowed">high_risk_allowed — high/critical after approval</option>
            <option value="no_changes">no_changes — block all mutations</option>
          </select>
        </div>
      </div>
      <p className="muted text-xs mb-3 -mt-1">Op mode gates SSH mutations independently of environment.</p>
      <div className="field"><label>Expires</label><input type="date" value={form.expires_at} onChange={(e) => set('expires_at', e.target.value)} /></div>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Renewal</label>
          <select value={form.renewal_cycle} onChange={(e) => set('renewal_cycle', e.target.value)}>
            <option value="monthly">monthly</option>
            <option value="quarterly">quarterly</option>
            <option value="yearly">yearly</option>
          </select>
        </div>
        <div className="field"><label>Currency</label><input value={form.currency} onChange={(e) => set('currency', e.target.value)} /></div>
      </div>
      <p className="text-sm mb-1">{t('billing')}</p>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Monthly cost</label><input value={form.monthly_cost} onChange={(e) => set('monthly_cost', e.target.value)} /></div>
        <div className="field"><label>Purchase price</label><input value={form.purchase_price} onChange={(e) => set('purchase_price', e.target.value)} /></div>
        <div className="field"><label>Purchase date</label><input type="date" value={form.purchase_date} onChange={(e) => set('purchase_date', e.target.value)} /></div>
        <div className="field"><label>Server type</label><input value={form.server_type} onChange={(e) => set('server_type', e.target.value)} /></div>
        <div className="field"><label>CPU cores</label><input value={form.cpu_cores} onChange={(e) => set('cpu_cores', e.target.value)} /></div>
        <div className="field"><label>RAM GB</label><input value={form.ram_gb} onChange={(e) => set('ram_gb', e.target.value)} /></div>
        <div className="field"><label>Disk GB</label><input value={form.disk_gb} onChange={(e) => set('disk_gb', e.target.value)} /></div>
        <div className="field"><label>Bandwidth</label><input value={form.bandwidth} onChange={(e) => set('bandwidth', e.target.value)} /></div>
        <div className="field"><label>IPv4</label><input value={form.ipv4} onChange={(e) => set('ipv4', e.target.value)} /></div>
        <div className="field"><label>IPv6</label><input value={form.ipv6} onChange={(e) => set('ipv6', e.target.value)} /></div>
        <div className="field"><label>Panel type</label><input value={form.panel_type} onChange={(e) => set('panel_type', e.target.value)} placeholder="none / cpanel / …" /></div>
        <div className="field"><label>Panel URL</label><input value={form.panel_url} onChange={(e) => set('panel_url', e.target.value)} /></div>
        <div className="field"><label>Panel user</label><input value={form.panel_username} onChange={(e) => set('panel_username', e.target.value)} /></div>
      </div>
      <label className="flex gap-2 text-sm mb-2"><input type="checkbox" checked={autoRenewal} onChange={(e) => setAutoRenewal(e.target.checked)} /> Auto renewal date</label>
      <label className="flex gap-2 text-sm mb-2"><input type="checkbox" checked={probeOn} onChange={(e) => setProbeOn(e.target.checked)} /> HTTP probe</label>
      <div className="field"><label>Probe URL</label><input value={form.http_probe_url} onChange={(e) => set('http_probe_url', e.target.value)} /></div>
      <div className="field"><label>Jump host</label><VPSPicker value={form.jump_host_id} onChange={(v) => set('jump_host_id', v)} /></div>
      <div className="field"><label>SOCKS5 proxy</label><input value={form.socks_proxy} onChange={(e) => set('socks_proxy', e.target.value)} placeholder="127.0.0.1:1080" /></div>
      <div className="field"><label>SFTP root</label><input value={form.sftp_root} onChange={(e) => set('sftp_root', e.target.value)} placeholder="/var/backups" /></div>
      <div className="field"><label>Maintenance windows</label>
        <MaintenanceWindowsEditor value={form.maintenance_windows} onChange={(v) => set('maintenance_windows', v)} />
      </div>
      <div className="field"><label>SSH password (encrypted; leave blank to keep)</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
      <div className="field"><label>Private key PEM (optional)</label>
        <textarea rows={3} value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" /></div>
      <div className="grid grid-cols-2 gap-3">
        <div className="field"><label>Key passphrase</label>
          <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></div>
        <div className="field"><label>Sudo password</label>
          <input type="password" value={sudoPass} onChange={(e) => setSudoPass(e.target.value)} /></div>
      </div>
      <div className="field"><label>Notes</label><textarea value={form.notes} onChange={(e) => set('notes', e.target.value)} rows={3} /></div>
      {err && <p className="error">{err}</p>}
      <button className="btn" type="submit">Save</button>
    </form>
  )
}

function VPSNew() {
  return <Shell><h2 className="text-xl mb-3">Add VPS</h2><VPSForm /></Shell>
}

function VPSDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const q = useQueryClient()
  const vps = useQuery({ queryKey: ['vps', id], queryFn: () => api<VPS>(`/api/vps/${id}`) })
  const [scanTick, setScanTick] = useState(0)
  const [msg, setMsg] = useState('')
  const [pendingFP, setPendingFP] = useState('')
  const [err, setErr] = useState('')
  useEffect(() => {
    const hash = window.location.hash.replace(/^#/, '')
    if (!vps.data || (hash !== 'host-ops' && hash !== 'expectations' && hash !== 'checkup')) return
    const t = window.setTimeout(() => {
      document.getElementById(hash)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 80)
    return () => window.clearTimeout(t)
  }, [vps.data, id])

  const test = async (confirm = false) => {
    setErr(''); setMsg('')
    try {
      const res = await api<{ output: string; fingerprint?: string }>(`/api/vps/${id}/test${confirm ? '?confirm_hostkey=1' : ''}`, { method: 'POST' })
      setMsg(res.output)
      q.invalidateQueries({ queryKey: ['vps', id] })
    } catch (ex) {
      const e = ex as Error & { status?: number; data?: { fingerprint?: string; error?: string } }
      if (e.status === 409 && e.data?.fingerprint) {
        setPendingFP(e.data.fingerprint)
      }
      setErr(e.message)
    }
  }

  const confirmHK = async () => {
    await api(`/api/vps/${id}/hostkey/confirm`, { method: 'POST' })
    setPendingFP('')
    await test(true)
  }

  const runScan = async () => {
    setErr('')
    try {
      await api(`/api/vps/${id}/scan`, { method: 'POST' })
      setScanTick((n) => n + 1)
      q.invalidateQueries({ queryKey: ['vps', id] })
      q.invalidateQueries({ queryKey: ['metrics', id] })
      setMsg('Scan completed')
    } catch (ex) { setErr((ex as Error).message) }
  }

  if (!vps.data) return <Shell><p className="muted">Loading…</p></Shell>
  const v = vps.data
  const readOnly = v.op_mode === 'readonly_monitor' || v.op_mode === 'no_changes'

  return (
    <Shell>
      <div className="flex gap-3 items-start mb-3">
        <div className="min-w-0">
          <h2 className="text-xl leading-tight">{v.name}</h2>
          <p className="muted text-sm mt-0.5">{v.ssh_user}@{v.host}:{v.ssh_port}{v.ssh_user === 'root' ? ' · root (high-risk)' : ''}</p>
          {(v.jump_host_id || v.socks_proxy) && (
            <p className="muted text-xs mt-1">
              {v.jump_host_id ? <>Jump: <Link to={`/vps/${v.jump_host_id}`}>#{v.jump_host_id}</Link></> : null}
              {v.jump_host_id && v.socks_proxy ? ' · ' : ''}
              {v.socks_proxy ? `SOCKS5 ${v.socks_proxy}` : ''}
            </p>
          )}
          {v.maintenance_windows && v.maintenance_windows !== '[]' && (
            <p className="muted text-xs mt-0.5 truncate" title={v.maintenance_windows}>Windows: {v.maintenance_windows}</p>
          )}
        </div>
        <div className="ml-auto flex flex-wrap gap-2">
          <button className="btn secondary" onClick={() => test(false)}>Test SSH</button>
          <button className="btn secondary" onClick={runScan}>Scan</button>
          <button className="btn secondary" disabled={readOnly} onClick={async () => {
            if (!confirm('Generate an Ed25519 key, install it, and delete the stored password?')) return
            try {
              await api(`/api/vps/${id}/convert-key`, { method: 'POST', body: JSON.stringify({ confirm: true }) })
              setMsg('Password replaced with a key')
            } catch (ex) { setErr((ex as Error).message) }
          }}>Password to key</button>
          {id && !readOnly && <DisablePasswordButton id={id} />}
          <Link className="btn secondary" to={`/vps/${id}/edit`}>Edit</Link>
          <button className="btn secondary" disabled={readOnly} onClick={async () => {
            if (!confirm(`Soft-delete ${v.name}? You can restore it from Trash.`)) return
            try {
              await api(`/api/vps/${id}`, { method: 'DELETE' })
              nav('/vps')
            } catch (ex) { setErr((ex as Error).message) }
          }}>Delete</button>
        </div>
      </div>
      {readOnly && (
        <p className="warn text-sm mb-3">op_mode={v.op_mode} — mutations blocked; Test SSH / Scan still allowed.</p>
      )}
      <div className="grid md:grid-cols-2 gap-3">
        <div className="card">
          <p className="text-sm">
            Status:{' '}
            <span className={`badge ${/online|ok|healthy/i.test(v.status || '') ? 'ok' : /off|fail|error/i.test(v.status || '') ? 'err' : ''}`}>
              {v.status}
            </span>
          </p>
          <p className="text-sm muted mt-1">Env: {v.environment} · Mode: {v.op_mode}</p>
          <p className="text-sm mt-1">
            {t('lastScan')}: {v.last_scan_at ? new Date(v.last_scan_at).toLocaleString() : t('neverScanned')}
            {' · '}Connect: {v.last_connect_at ? new Date(v.last_connect_at).toLocaleString() : '—'}
          </p>
          <p className="text-sm mt-1">TCP: {v.tcp_reachable == null ? '—' : v.tcp_reachable ? 'ok' : 'fail'}
            {v.tcp_checked_at ? ` @ ${new Date(v.tcp_checked_at).toLocaleString()}` : ''}
            {' · '}HTTP probe: {v.http_probe_enabled ? (v.http_probe_healthy ? 'ok' : 'fail') : 'disabled'}
            {v.http_probe_url ? ` · ${v.http_probe_url}` : ''}
          </p>
          {(v.http_probe_last_at || v.http_probe_last_error) && (
            <p className="muted text-xs mt-1">
              Last probe: {v.http_probe_last_at ? new Date(v.http_probe_last_at).toLocaleString() : '—'}
              {v.http_probe_last_error ? ` · ${v.http_probe_last_error}` : ''}
            </p>
          )}
          <MaintenanceStatusBadge id={String(v.id)} />
          <p className="muted text-sm mt-2">Host key: {v.host_key_fp || 'unset'}</p>
          {v.host_key_pending && <p className="warn text-sm">Pending: {v.host_key_pending}</p>}
          {(v.host_key_fp || v.host_key_pending) && (
            <button className="btn secondary mt-2 mr-2" onClick={async () => {
              if (!confirm('Clear pinned host key? Next SSH will require re-confirming the fingerprint.')) return
              try {
                await api(`/api/vps/${id}/hostkey/clear`, { method: 'POST', body: JSON.stringify({ confirm: true }) })
                q.invalidateQueries({ queryKey: ['vps', id] })
                setMsg('Host key cleared')
              } catch (ex) { setErr((ex as Error).message) }
            }}>Clear host key</button>
          )}
          <div className="flex flex-wrap gap-2 mt-2">
            {(['ssh_password', 'ssh_private_key', 'key_passphrase', 'sudo_password'] as const).map((kind) => (
              <button key={kind} className="btn secondary" onClick={async () => {
                try {
                  const token = await unlockViewToken()
                  const r = await api<{ value: string }>(`/api/vps/${id}/reveal/${kind}`, {
                    method: 'POST', headers: { 'X-View-Token': token },
                  })
                  setMsg(`${kind}: ${r.value}`)
                } catch (ex) {
                  const msg = formatApiError(ex)
                  setErr(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
                }
              }}>{t('reveal')} {kind.replace(/_/g, ' ')}</button>
            ))}
          </div>
          {id && !readOnly && <CredsEditor id={id} onDone={(m) => { setMsg(m); setErr('') }} onErr={setErr} />}
          <div className="mt-3 border-t border-[var(--border)] pt-3 text-sm">
            <h3 className="mb-1">{t('billing')}</h3>
            <p className="muted text-xs">
              {[
                v.expires_at ? `exp ${v.expires_at}` : '',
                v.monthly_cost != null ? `${v.currency || ''} ${v.monthly_cost}/mo` : '',
                v.purchase_price != null ? `buy ${v.purchase_price}` : '',
                v.purchase_date || '',
                v.server_type || '',
                v.cpu_cores != null ? `${v.cpu_cores}c` : '',
                v.ram_gb != null ? `${v.ram_gb}G` : '',
                v.disk_gb != null ? `${v.disk_gb}G disk` : '',
                v.bandwidth || '',
                v.ipv4 || '',
                v.ipv6 || '',
                v.panel_type ? `panel ${v.panel_type}` : '',
                v.panel_username ? `user ${v.panel_username}` : '',
              ].filter(Boolean).join(' · ') || '—'}
            </p>
            {v.panel_url && <p className="text-xs mt-1 truncate"><a href={v.panel_url} target="_blank" rel="noreferrer">{v.panel_url}</a></p>}
          </div>
        </div>
        <div className="card">
          {pendingFP && (
            <div className="mb-3">
              <p className="mb-2">Confirm new host key fingerprint?</p>
              <code className="text-xs break-all block mb-2">{pendingFP}</code>
              <button className="btn" onClick={confirmHK}>Confirm fingerprint</button>
            </div>
          )}
          {msg && <pre className="text-xs whitespace-pre-wrap">{msg}</pre>}
          {err && <p className="error">{err}</p>}
        </div>
      </div>
      {id && <MetricsHistory id={id} refresh={scanTick} />}
      {id && <ScanDiff id={id} refresh={scanTick} />}
      {id && <ChangeSnapshots id={id} />}
      {id && <CheckupPanel id={id} refresh={scanTick} opMode={v.op_mode} onScanned={() => { setScanTick((n) => n + 1); q.invalidateQueries({ queryKey: ['vps', id] }) }} />}
      {id && <ExpectationsPanel id={id} />}
      {id && <div id="host-ops"><HostOps id={id} refresh={scanTick} opMode={v.op_mode} /></div>}
      {id && <SFTPGate id={id} />}
      {id && <WebSSHGate id={id} />}
    </Shell>
  )
}

function CredsEditor({ id, onDone, onErr }: { id: string; onDone: (m: string) => void; onErr: (m: string) => void }) {
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [sudoPass, setSudoPass] = useState('')
  const [open, setOpen] = useState(false)
  if (!open) {
    return <button className="btn secondary mt-2 ml-2" onClick={() => setOpen(true)}>Update credentials</button>
  }
  return (
    <div className="mt-3 border-t border-[var(--border)] pt-3">
      <p className="text-sm mb-2">Update encrypted credentials (blank fields kept)</p>
      <div className="field"><label>SSH password</label><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
      <div className="field"><label>Private key</label><textarea rows={3} value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} /></div>
      <div className="field"><label>Key passphrase</label><input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></div>
      <div className="field"><label>Sudo password</label><input type="password" value={sudoPass} onChange={(e) => setSudoPass(e.target.value)} /></div>
      <div className="flex gap-2">
        <button className="btn" onClick={async () => {
          try {
            await api(`/api/vps/${id}/credentials`, {
              method: 'POST',
              body: JSON.stringify({
                password: password || undefined,
                private_key: privateKey || undefined,
                passphrase: passphrase || undefined,
                sudo_password: sudoPass || undefined,
              }),
            })
            setPassword(''); setPrivateKey(''); setPassphrase(''); setSudoPass('')
            setOpen(false)
            onDone('Credentials updated')
          } catch (ex) { onErr((ex as Error).message) }
        }}>Save credentials</button>
        <button className="btn secondary" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  )
}

function WebSSHGate({ id }: { id: string }) {
  const me = useMe()
  const feat = useQuery({ queryKey: ['features'], queryFn: () => api<{ webssh_enabled: boolean; sftp_enabled: boolean }>('/api/settings/features') })
  if (feat.isLoading) return null
  if (!feat.data?.webssh_enabled) {
    return (
      <div className="card mt-4">
        <h3 className="mb-1">WebSSH</h3>
        <p className="muted text-sm">{t('featureDisabled')} — {t('featureConfigHint')}</p>
      </div>
    )
  }
  if (me.data?.vault !== 'unlocked') {
    return (
      <div className="card mt-4">
        <h3 className="mb-1">WebSSH</h3>
        <p className="warn text-sm mb-2">{t('vaultLockedHint')}</p>
        <Link className="btn secondary" to="/vault">{t('unlockVault')}</Link>
      </div>
    )
  }
  return <WebSSH id={id} enabled />
}

function SFTPGate({ id }: { id: string }) {
  const me = useMe()
  const feat = useQuery({ queryKey: ['features'], queryFn: () => api<{ sftp_enabled: boolean }>('/api/settings/features') })
  if (feat.isLoading) return null
  if (!feat.data?.sftp_enabled) {
    return (
      <div className="card mt-4">
        <h3 className="mb-1">SFTP</h3>
        <p className="muted text-sm">{t('featureDisabled')} — {t('featureConfigHint')}</p>
      </div>
    )
  }
  if (me.data?.vault !== 'unlocked') {
    return (
      <div className="card mt-4">
        <h3 className="mb-1">SFTP</h3>
        <p className="warn text-sm mb-2">{t('vaultLockedHint')}</p>
        <Link className="btn secondary" to="/vault">{t('unlockVault')}</Link>
      </div>
    )
  }
  return <SFTPBrowser id={id} />
}

function VPSEdit() {
  const { id } = useParams()
  const vps = useQuery({ queryKey: ['vps', id], queryFn: () => api<VPS>(`/api/vps/${id}`) })
  if (!vps.data) return <Shell><p className="muted">Loading…</p></Shell>
  return <Shell><h2 className="text-xl mb-3">Edit {vps.data.name}</h2><VPSForm initial={vps.data} /></Shell>
}

function auditTargetLink(type: string, id: string) {
  if (!id) return <span className="muted">{type || '—'}</span>
  if (type === 'vps') return <Link to={`/vps/${id}`}>{type} {id}</Link>
  if (type === 'task') return <Link to={`/tasks/${id}`}>{type} {id.slice(0, 8)}</Link>
  if (type === 'script') return <Link to={`/scripts/${id}`}>{type} {id}</Link>
  if (type === 'website') return <Link to={`/websites?highlight=${id}`}>{type} {id}</Link>
  if (type === 'provider') return <Link to="/providers">{type} {id}</Link>
  return <span className="muted">{type} {id}</span>
}

function AuditPage() {
  const initialQ = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('q') || '' : ''
  const initialResult = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('result') || '' : ''
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [risk, setRisk] = useState('')
  const [result, setResult] = useState(initialResult)
  const [q, setQ] = useState(initialQ)
  const [rows, setRows] = useState<AuditEntry[]>([])
  const [offset, setOffset] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const pageSize = 100
  const qs = new URLSearchParams()
  if (action) qs.set('action', action)
  if (actor) qs.set('actor', actor)
  if (risk) qs.set('risk', risk)
  if (result) qs.set('result', result)
  if (q) qs.set('q', q)
  const actions = useQuery({
    queryKey: ['audit-actions'],
    queryFn: () => api<string[]>('/api/audit/actions'),
  })
  const list = useQuery({
    queryKey: ['audit', action, actor, risk, result, q],
    queryFn: () => api<AuditEntry[]>(`/api/audit?${qs.toString()}&limit=${pageSize}&offset=0`),
  })
  useEffect(() => {
    const data = list.data ?? []
    setRows(data)
    setOffset(data.length)
    setHasMore(data.length >= pageSize)
  }, [list.data])
  const loadMore = async () => {
    setLoadingMore(true)
    try {
      const more = await api<AuditEntry[]>(`/api/audit?${qs.toString()}&limit=${pageSize}&offset=${offset}`)
      setRows((cur) => [...cur, ...more])
      setOffset((n) => n + more.length)
      setHasMore(more.length >= pageSize)
    } finally { setLoadingMore(false) }
  }
  const [chain, setChain] = useState('')
  const auditRiskBadge = (r?: string) => (r === 'high' || r === 'critical' ? 'err' : r === 'medium' ? 'warn' : '')
  const auditResultBadge = (r?: string) => {
    if (!r) return ''
    if (/ok|success|pass/i.test(r)) return 'ok'
    if (/fail|error|deny|reject/i.test(r)) return 'err'
    return 'warn'
  }
  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('audit')}</h2>
        <select className="field" style={{ width: 200 }} value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">All actions</option>
          {(actions.data ?? []).map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <input className="field" style={{ width: 120 }} placeholder="Actor" value={actor} onChange={(e) => setActor(e.target.value)} />
        <select className="field" style={{ width: 120 }} value={risk} onChange={(e) => setRisk(e.target.value)}>
          <option value="">All risk</option>
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
          <option value="critical">critical</option>
        </select>
        <select className="field" style={{ width: 120 }} value={result} onChange={(e) => {
          const v = e.target.value
          setResult(v)
          const sp = new URLSearchParams(window.location.search)
          if (v) sp.set('result', v); else sp.delete('result')
          const qstr = sp.toString()
          window.history.replaceState(null, '', qstr ? `/audit?${qstr}` : '/audit')
        }}>
          <option value="">{t('allResults')}</option>
          <option value="success">{t('resultOK')}</option>
          <option value="failed">{t('resultFail')}</option>
        </select>
        <input className="field" style={{ width: 160 }} placeholder={t('search')} value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="btn secondary" onClick={async () => {
          try {
            const r = await api<{ ok: boolean }>('/api/audit/verify')
            setChain(r.ok ? 'Hash chain intact' : 'Hash chain mismatch')
          } catch (ex) { setChain((ex as Error).message) }
        }}>Verify chain</button>
        <button className="btn secondary" onClick={async () => {
          const res = await fetch(`/api/audit/export?${qs.toString()}`, { credentials: 'include' })
          if (!res.ok) { setChain('export failed'); return }
          const blob = await res.blob()
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = 'vpshub-audit.csv'
          a.click()
          URL.revokeObjectURL(url)
        }}>{t('export')} CSV</button>
      </div>
      {chain && (
        <p className="mb-2 text-sm">
          <span className={`badge ${/intact/i.test(chain) ? 'ok' : 'err'}`}>{chain}</span>
        </p>
      )}
      <div className="card overflow-x-auto">
        <table className="table">
          <thead><tr><th>Time</th><th>Actor</th><th>IP</th><th>Action</th><th>Target</th><th>Task</th><th>Risk</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td className="muted text-xs">{new Date(e.created_at).toLocaleString()}</td>
                <td>{e.actor}</td>
                <td className="muted text-xs">{e.ip || '—'}</td>
                <td className="text-sm">{e.action}</td>
                <td>{auditTargetLink(e.target_type, e.target_id)}</td>
                <td>{e.task_id ? <Link to={`/tasks/${e.task_id}`}><code>{e.task_id.slice(0, 8)}</code></Link> : '—'}</td>
                <td><span className={`badge ${auditRiskBadge(e.risk_level)}`}>{e.risk_level || '—'}</span></td>
                <td>
                  <span className={`badge ${auditResultBadge(e.result)}`}>{e.result || '—'}</span>
                  {e.failure_reason ? <span className="error text-xs block mt-0.5">{e.failure_reason}</span> : null}
                </td>
                <td className="muted text-xs max-w-xs truncate" title={e.detail}>{e.detail || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {hasMore && (
          <button className="btn secondary mt-3" disabled={loadingMore} onClick={loadMore}>
            {loadingMore ? t('loading') : t('loadMore')}
          </button>
        )}
      </div>
    </Shell>
  )
}

function matrixBadge(status?: string) {
  if (!status) return ''
  if (status === 'running') return 'ok'
  if (status === 'stopped' || status === 'error' || status === 'abnormal') return 'err'
  if (status === 'installed' || status === 'unknown') return 'warn'
  return ''
}

function MatrixPage() {
  const nav = useNavigate()
  const [environment, setEnvironment] = useState('')
  const [group, setGroup] = useState('')
  const [status, setStatus] = useState('')
  const [tag, setTag] = useState('')
  const [problemsOnly, setProblemsOnly] = useState(false)
  const [scanMsg, setScanMsg] = useState('')
  const [fleetScript, setFleetScript] = useState('security-baseline')
  const qs = new URLSearchParams()
  if (environment) qs.set('environment', environment)
  if (group) qs.set('group', group)
  if (status) qs.set('status', status)
  if (tag) qs.set('tag', tag)
  const inv = useQuery({
    queryKey: ['matrix'],
    queryFn: () => api<{ vps_id: number; service_type: string; status: string; version?: string }[]>('/api/matrix'),
  })
  const vps = useQuery({
    queryKey: ['vps', 'matrix', environment, group, status, tag],
    queryFn: () => api<VPS[]>(`/api/vps?${qs.toString()}`),
  })
  const services = useMemo(() => {
    const set = new Set<string>()
    const ids = new Set((vps.data ?? []).map((v) => v.id))
    for (const i of inv.data ?? []) {
      if (ids.size === 0 || ids.has(i.vps_id)) set.add(i.service_type)
    }
    return [...set].sort()
  }, [inv.data, vps.data])
  const cell = (vpsId: number, svc: string) =>
    (inv.data ?? []).find((i) => i.vps_id === vpsId && i.service_type === svc)
  const isProblem = (st?: string) => !!st && /fail|stop|error|down|inactive|exited|unhealthy|abnormal/i.test(st)
  const rows = (vps.data ?? []).filter((v) => {
    if (!problemsOnly) return true
    return services.some((s) => isProblem(cell(v.id, s)?.status))
  })
  const scanFiltered = async () => {
    setScanMsg('')
    const ids = rows.map((v) => v.id)
    if (!ids.length) { setScanMsg(t('emptyVPS')); return }
    try {
      const tsk = await api<{ id: string }>('/api/vps/batch-scan', { method: 'POST', body: JSON.stringify({ ids }) })
      nav(`/tasks/${tsk.id}`)
    } catch (ex) {
      const msg = formatApiError(ex)
      setScanMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
    }
  }
  const runFleetScript = async () => {
    setScanMsg('')
    const ids = rows.map((v) => v.id)
    if (!ids.length) { setScanMsg(t('emptyVPS')); return }
    try {
      const scripts = await api<{ id: number; name: string; status: string }[]>('/api/scripts')
      const sc = (scripts ?? []).find((s) => s.name === fleetScript && (s.status === 'published' || s.status === 'approved'))
      if (!sc) { setScanMsg(`script "${fleetScript}" not published`); return }
      const tsk = await api<{ id: string }>('/api/tasks', {
        method: 'POST',
        body: JSON.stringify({
          type: 'script', vps_ids: ids, dry_run: true, risk_level: 'low', confirm: false,
          payload: { script_id: sc.id, params: {} },
        }),
      })
      nav(`/tasks/${tsk.id}`)
    } catch (ex) {
      const msg = formatApiError(ex)
      setScanMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
    }
  }

  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('matrix')}</h2>
        <select className="field" style={{ width: 130 }} value={environment} onChange={(e) => setEnvironment(e.target.value)}>
          <option value="">{t('allEnv')}</option>
          <option value="production">production</option>
          <option value="testing">testing</option>
        </select>
        <select className="field" style={{ width: 130 }} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">{t('allStatus')}</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="unknown">unknown</option>
        </select>
        <input className="field" style={{ width: 120 }} placeholder={t('group')} value={group} onChange={(e) => setGroup(e.target.value)} />
        <input className="field" style={{ width: 120 }} placeholder={t('tag')} value={tag} onChange={(e) => setTag(e.target.value)} />
        <label className="btn secondary">
          <input type="checkbox" className="mr-1" checked={problemsOnly} onChange={(e) => setProblemsOnly(e.target.checked)} />
          {t('problemOnly')}
        </label>
        <button className="btn secondary" disabled={!rows.length} onClick={scanFiltered}>{t('scanFiltered')}</button>
        <select className="field" style={{ width: 170 }} value={fleetScript} onChange={(e) => setFleetScript(e.target.value)} title={t('fleetScripts')}>
          <option value="security-baseline">security-baseline</option>
          <option value="docker-prune-dry">docker-prune-dry</option>
          <option value="process-top">process-top</option>
          <option value="auth-log-tail">auth-log-tail</option>
          <option value="conn-summary">conn-summary</option>
        </select>
        <button className="btn secondary" disabled={!rows.length} onClick={runFleetScript}>{t('runPublishedScript')}</button>
      </div>
      {scanMsg && <p className="muted text-sm mb-2">{scanMsg}</p>}
      <div className="card overflow-x-auto">
        <table className="table matrix">
          <thead>
            <tr>
              <th>VPS</th>
              {services.map((s) => <th key={s}>{s}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((v) => (
              <tr key={v.id}>
                <td><Link to={`/vps/${v.id}#host-ops`}>{v.name}</Link>
                  <div className="muted text-xs">{v.environment} · {v.status}</div>
                </td>
                {services.map((s) => {
                  const c = cell(v.id, s)
                  const badge = (
                    <span className={`badge ${matrixBadge(c?.status)}`}>{c?.status ?? '—'}</span>
                  )
                  return (
                    <td key={s} title={c?.version || undefined}>
                      {c ? <Link to={`/vps/${v.id}#host-ops`}>{badge}</Link> : badge}
                      {c?.version && <div className="muted text-xs mt-0.5">{c.version}</div>}
                      {c && isProblem(c.status) && (
                        <div className="mt-0.5">
                          <Link className="text-xs" to={`/tasks?type=upgrade&module=${encodeURIComponent(s)}&vps=${v.id}`}>{t('upgradeTask')}</Link>
                        </div>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
        {!services.length && <p className="muted">No inventory yet — run a scan on a VPS.</p>}
      </div>
    </Shell>
  )
}

function TasksPage() {
  const sp0 = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : new URLSearchParams()
  const initialStatus = sp0.get('status') || ''
  const [statusFilter, setStatusFilter] = useState(initialStatus)
  const pageSize = 50
  const [taskRows, setTaskRows] = useState<{ id: string; type: string; status: string; risk_level: string; created_at: string; dry_run?: boolean }[]>([])
  const [taskOffset, setTaskOffset] = useState(0)
  const [taskHasMore, setTaskHasMore] = useState(true)
  const [loadingMoreTasks, setLoadingMoreTasks] = useState(false)
  const list = useQuery({
    queryKey: ['tasks', statusFilter],
    queryFn: () => {
      const qs = new URLSearchParams()
      if (statusFilter) qs.set('status', statusFilter)
      qs.set('limit', String(pageSize))
      qs.set('offset', '0')
      return api<{ id: string; type: string; status: string; risk_level: string; created_at: string; dry_run?: boolean }[]>(
        `/api/tasks?${qs.toString()}`,
      )
    },
    refetchInterval: (q) => {
      if (typeof document !== 'undefined' && document.hidden) return false
      const rows = q.state.data ?? []
      const active = rows.some((t) => t.status === 'pending' || t.status === 'running' || t.status === 'waiting_approval')
      return active ? 3000 : false
    },
  })
  useEffect(() => {
    const data = list.data ?? []
    setTaskRows(data)
    setTaskOffset(data.length)
    setTaskHasMore(data.length >= pageSize)
  }, [list.data])
  const loadMoreTasks = async () => {
    setLoadingMoreTasks(true)
    try {
      const qs = new URLSearchParams()
      if (statusFilter) qs.set('status', statusFilter)
      qs.set('limit', String(pageSize))
      qs.set('offset', String(taskOffset))
      const more = await api<{ id: string; type: string; status: string; risk_level: string; created_at: string; dry_run?: boolean }[]>(
        `/api/tasks?${qs.toString()}`,
      )
      setTaskRows((cur) => [...cur, ...more])
      setTaskOffset((n) => n + more.length)
      setTaskHasMore(more.length >= pageSize)
    } finally { setLoadingMoreTasks(false) }
  }
  const vps = useQuery({ queryKey: ['vps'], queryFn: () => api<VPS[]>('/api/vps') })
  const [type, setType] = useState(sp0.get('type') || 'shell')
  const [cmd, setCmd] = useState('uname -a')
  const [scriptId, setScriptId] = useState('')
  const scripts = useQuery({
    queryKey: ['scripts', 'runnable'],
    queryFn: () => api<{ id: number; name: string; status: string; params_schema?: string; allow_batch?: boolean; allow_production?: boolean }[]>('/api/scripts'),
    enabled: type === 'script',
  })
  const runnableScripts = (scripts.data ?? []).filter((s) => s.status === 'approved' || s.status === 'published')
  const selectedScript = runnableScripts.find((s) => String(s.id) === scriptId)
  const scriptDetail = useQuery({
    queryKey: ['script', scriptId],
    queryFn: () => api<{ id: number; params_schema?: string; allow_batch?: boolean; allow_production?: boolean }>(`/api/scripts/${scriptId}`),
    enabled: type === 'script' && !!scriptId,
  })
  const paramDefs = parseParamsSchema(scriptDetail.data?.params_schema ?? selectedScript?.params_schema)
  const [paramValues, setParamValues] = useState<Record<string, string>>({})
  const [advancedJSON, setAdvancedJSON] = useState(false)
  const [moduleName, setModuleName] = useState(sp0.get('module') || 'xray')
  const [version, setVersion] = useState('')
  const [sha, setSha] = useState('')
  const [url, setUrl] = useState('')
  const [pm, setPm] = useState('apt')
  const [scope, setScope] = useState('all')
  const [planPreview, setPlanPreview] = useState('')
  const modules = useQuery({
    queryKey: ['modules'],
    queryFn: () => api<{ name: string; dependencies?: string[]; config_paths?: string[]; install_bin?: string; risk_level?: string }[]>('/api/modules'),
    enabled: type === 'upgrade',
  })
  const impact = useQuery({
    queryKey: ['impact', moduleName],
    queryFn: () => api<{ depends_on: string[]; depended_on_by: string[] }>(`/api/services/impact?name=${encodeURIComponent(moduleName)}`),
    enabled: type === 'upgrade' && !!moduleName,
  })
  const matrix = useQuery({
    queryKey: ['matrix', 'upgrade-hint'],
    queryFn: () => api<{ vps_id: number; service_type: string; version?: string }[]>('/api/matrix'),
    enabled: type === 'upgrade',
  })
  const initialVps = sp0.get('vps') ? Number(sp0.get('vps')) : NaN
  const [ids, setIds] = useState<number[]>(Number.isFinite(initialVps) && initialVps > 0 ? [initialVps] : [])
  const [canary, setCanary] = useState<number[]>([])
  const [rollBatch, setRollBatch] = useState('0')
  const [concurrency, setConcurrency] = useState('2')
  const [failThreshold, setFailThreshold] = useState('0.5')
  const [retryMax, setRetryMax] = useState('0')
  const [timeoutSec, setTimeoutSec] = useState('120')
  const [dry, setDry] = useState(true)
  const [onFail, setOnFail] = useState<'pause' | 'continue'>('pause')
  const [scriptParams, setScriptParams] = useState('{}')
  const [reboot, setReboot] = useState(false)
  const [msg, setMsg] = useState('')
  useEffect(() => {
    if (!scriptId) { setParamValues({}); return }
    const next: Record<string, string> = {}
    for (const d of paramDefs) next[d.name] = paramValues[d.name] ?? ''
    setParamValues(next)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when script/schema changes
  }, [scriptId, scriptDetail.data?.params_schema])
  const exportTask = async (id: string) => {
    try {
      const res = await fetch(`/api/tasks/${id}/export`, { credentials: 'include' })
      if (!res.ok) { setMsg('export failed'); return }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `task-${id}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (ex) { setMsg((ex as Error).message) }
  }

  const scriptFlags = {
    allow_batch: scriptDetail.data?.allow_batch ?? selectedScript?.allow_batch,
    allow_production: scriptDetail.data?.allow_production ?? selectedScript?.allow_production,
  }
  const selectedModule = (modules.data ?? []).find((m) => m.name === moduleName)
  const matrixVersion = ids.length === 1
    ? (matrix.data ?? []).find((r) => r.vps_id === ids[0] && r.service_type === moduleName)?.version
    : undefined

  const create = async (outside = false) => {
    setMsg('')
    let payload: Record<string, unknown> = { command: cmd }
    if (type === 'script') {
      if (ids.length > 1 && scriptFlags.allow_batch === false) {
        setMsg(t('scriptNoBatch')); return
      }
      const prodBlocked = (vps.data ?? []).filter((v) => ids.includes(v.id) && v.environment === 'production' && scriptFlags.allow_production === false)
      if (prodBlocked.length) {
        setMsg(t('scriptNoProd').replace('{names}', prodBlocked.map((v) => v.name).join(', '))); return
      }
      let params: Record<string, string> = {}
      if (advancedJSON || !paramDefs.length) {
        try { params = JSON.parse(scriptParams || '{}') } catch { setMsg('script params must be JSON'); return }
      } else {
        for (const d of paramDefs) {
          if (d.required && !(paramValues[d.name] || '').trim()) {
            setMsg(`Missing required param: ${d.name}`)
            return
          }
          if ((paramValues[d.name] || '').trim()) params[d.name] = paramValues[d.name]
        }
      }
      payload = { script_id: Number(scriptId), params }
    }
    if (type === 'sysupgrade') payload = { package_manager: pm, scope, reboot }
    if (type === 'upgrade') payload = { module: moduleName, version, sha256: sha, download_url: url }
    try {
      const t = await api<{ id: string }>('/api/tasks', {
        method: 'POST',
        body: JSON.stringify({
          type, vps_ids: ids, dry_run: dry, risk_level: dry ? 'low' : 'high', confirm: !dry,
          confirm_outside_window: outside, payload,
          concurrency: Math.max(1, parseInt(concurrency, 10) || 2),
          roll_batch: Math.max(0, parseInt(rollBatch, 10) || 0),
          canary_vps_ids: canary,
          fail_threshold: Math.min(1, Math.max(0.01, parseFloat(failThreshold) || 0.5)),
          retry_max: Math.min(9, Math.max(0, parseInt(retryMax, 10) || 0)),
          timeout_sec: Math.max(10, parseInt(timeoutSec, 10) || 120),
          on_fail: onFail,
        }),
      })
      setMsg(`Task ${t.id} created`)
      list.refetch()
    } catch (ex) {
      const e = ex as Error & { status?: number; data?: { error?: string; vps?: string } }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await create(true)
        return
      }
      if (e.status === 403 && (e.data?.error === 'op_mode_blocks' || e.message.includes('op_mode'))) {
        setMsg(e.data?.vps
          ? `Blocked: VPS "${e.data.vps}" op_mode rejects this change (readonly / risk too high)`
          : e.message)
        return
      }
      const msg = formatApiError(e)
      setMsg(msg === 'vault_locked' ? t('vaultLockedHint') : msg)
    }
  }

  const blockedTargets = (vps.data ?? []).filter((v) => {
    if (!ids.includes(v.id)) return false
    if (v.op_mode === 'readonly_monitor' || v.op_mode === 'no_changes') return true
    if (!dry && v.op_mode !== 'high_risk_allowed') return true
    return false
  })

  const taskStatusBadge = (st: string) => {
    if (st === 'success') return 'ok'
    if (st === 'failed' || st === 'timeout' || st === 'cancelled') return 'err'
    if (st === 'waiting_approval' || st === 'partial' || st === 'running' || st === 'pending') return 'warn'
    return ''
  }
  const riskBadge = (r: string) => (r === 'high' || r === 'critical' ? 'err' : r === 'medium' ? 'warn' : '')

  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('tasks')}</h2>
        <select className="field" style={{ width: 180 }} value={statusFilter} onChange={(e) => {
          const v = e.target.value
          setStatusFilter(v)
          const url = v ? `/tasks?status=${encodeURIComponent(v)}` : '/tasks'
          window.history.replaceState(null, '', url)
        }}>
          <option value="">{t('allStatus')}</option>
          <option value="waiting_approval">waiting_approval</option>
          <option value="pending">pending</option>
          <option value="running">running</option>
          <option value="success">success</option>
          <option value="failed">failed</option>
          <option value="partial">partial</option>
          <option value="skipped">skipped</option>
          <option value="timeout">timeout</option>
          <option value="cancelled">cancelled</option>
        </select>
      </div>
      <div className="card mb-4">
        <h3 className="form-section-title">{t('newTask')}</h3>
        <div className="field"><label>{t('type')}</label>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="shell">shell</option>
            <option value="script">script</option>
            <option value="sysupgrade">sysupgrade</option>
            <option value="upgrade">upgrade</option>
          </select>
        </div>
        {type === 'shell' && <div className="field"><label>{t('command')}</label><textarea value={cmd} onChange={(e) => setCmd(e.target.value)} rows={3} /></div>}
        {type === 'script' && (
          <>
            <div className="field"><label>{t('selectScript')}</label>
              <select value={scriptId} onChange={(e) => setScriptId(e.target.value)}>
                <option value="">—</option>
                {runnableScripts.map((s) => <option key={s.id} value={s.id}>{s.name} (#{s.id})</option>)}
              </select>
            </div>
            {!!paramDefs.length && !advancedJSON && (
              <div className="grid md:grid-cols-2 gap-2 mb-2">
                {paramDefs.map((d) => (
                  <div className="field !mb-0" key={d.name}>
                    <label>{d.name}{d.required ? ' *' : ''}</label>
                    <input value={paramValues[d.name] ?? ''} onChange={(e) => setParamValues((cur) => ({ ...cur, [d.name]: e.target.value }))} />
                  </div>
                ))}
              </div>
            )}
            {(advancedJSON || !paramDefs.length) && (
              <div className="field"><label>{t('paramsJSON')}</label><input value={scriptParams} onChange={(e) => setScriptParams(e.target.value)} placeholder='{"MSG":"hello"}' /></div>
            )}
            {!!paramDefs.length && (
              <label className="flex items-center gap-2 mb-2 text-sm muted">
                <input type="checkbox" checked={advancedJSON} onChange={(e) => setAdvancedJSON(e.target.checked)} /> {t('advancedJSON')}
              </label>
            )}
            {scriptId && (
              <p className="muted text-xs mb-2">
                allow_batch={String(scriptFlags.allow_batch ?? '—')} · allow_production={String(scriptFlags.allow_production ?? '—')}
                {ids.length > 1 && scriptFlags.allow_batch === false ? <> · <span className="warn">{t('scriptNoBatch')}</span></> : null}
              </p>
            )}
          </>
        )}
        {type === 'sysupgrade' && (
          <>
            <div className="grid md:grid-cols-2 gap-3">
              <div className="field"><label>{t('packageManager')}</label>
                <select value={pm} onChange={(e) => setPm(e.target.value)}>
                  <option value="apt">apt</option><option value="dnf">dnf</option><option value="yum">yum</option><option value="apk">apk</option><option value="pacman">pacman</option>
                </select>
              </div>
              <div className="field"><label>{t('scope')}</label>
                <select value={scope} onChange={(e) => setScope(e.target.value)}>
                  <option value="all">all</option>
                  <option value="security">security</option>
                </select>
              </div>
            </div>
            <label className="flex items-center gap-2 mb-2 text-sm">
              <input type="checkbox" checked={reboot} onChange={(e) => setReboot(e.target.checked)} />
              Reboot if required (ignored for production)
            </label>
            <p className="warn text-sm mb-2">
              System upgrades can restart services, break reverse proxies, and require reboot.
              Prefer dry-run first; production never auto-reboots. Check maintenance windows before running.
            </p>
          </>
        )}
        {type === 'upgrade' && (
          <div className="grid md:grid-cols-2 gap-3">
            <div className="field"><label>{t('module')}</label>
              <select value={moduleName} onChange={(e) => setModuleName(e.target.value)}>
                {(modules.data ?? []).map((m) => <option key={m.name} value={m.name}>{m.name}</option>)}
                {!(modules.data ?? []).some((m) => m.name === moduleName) && moduleName && (
                  <option value={moduleName}>{moduleName}</option>
                )}
              </select>
            </div>
            <div className="field"><label>{t('version')}</label><input value={version} onChange={(e) => setVersion(e.target.value)} /></div>
            <div className="field"><label>SHA256</label><input value={sha} onChange={(e) => setSha(e.target.value)} /></div>
            <div className="field"><label>{t('downloadUrl')}</label><input value={url} onChange={(e) => setUrl(e.target.value)} /></div>
          </div>
        )}
        {type === 'upgrade' && (
          <div className="muted text-sm mb-3 space-y-1">
            {matrixVersion && <p>{t('currentModuleVersion')}: <code>{matrixVersion}</code></p>}
            {selectedModule && (
              <p>
                risk={selectedModule.risk_level || '—'}
                {selectedModule.install_bin ? ` · bin ${selectedModule.install_bin}` : ''}
                {selectedModule.config_paths?.length ? ` · configs ${selectedModule.config_paths.join(', ')}` : ''}
              </p>
            )}
            <p>Depends on: {(impact.data?.depends_on?.length ? impact.data.depends_on : selectedModule?.dependencies)?.join(', ') || 'none'}</p>
            <p>May affect: {impact.data?.depended_on_by?.join(', ') || 'none listed'}</p>
            <button className="btn secondary" type="button" onClick={async () => {
              setPlanPreview('')
              try {
                const r = await api<{ plan: string }>('/api/modules/upgrade-plan', {
                  method: 'POST',
                  body: JSON.stringify({ module: moduleName, version, sha256: sha, download_url: url }),
                })
                setPlanPreview(r.plan || '(empty plan)')
              } catch (ex) { setPlanPreview((ex as Error).message) }
            }}>{t('previewPlan')}</button>
            {planPreview && <pre className="text-xs whitespace-pre-wrap mt-2 max-h-48 overflow-auto border border-[var(--border)] rounded-[var(--radius)] p-3 bg-[var(--panel-soft)]">{planPreview}</pre>}
          </div>
        )}
        <div className="field"><label>{t('targets')}</label>
          <select multiple className="min-h-24" value={ids.map(String)} onChange={(e) => setIds([...e.target.selectedOptions].map((o) => Number(o.value)))}>
            {(vps.data ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
          </select>
        </div>
        <div className="field"><label>{t('canary')}</label>
          <select multiple className="min-h-20" value={canary.map(String)} onChange={(e) => setCanary([...e.target.selectedOptions].map((o) => Number(o.value)))}>
            {ids.map((id) => {
              const v = (vps.data ?? []).find((x) => x.id === id)
              return <option key={id} value={id}>{v?.name ?? id}</option>
            })}
          </select>
        </div>
        <div className="grid md:grid-cols-3 gap-3">
          <div className="field"><label>{t('concurrency')}</label><input value={concurrency} onChange={(e) => setConcurrency(e.target.value)} /></div>
          <div className="field"><label>{t('rollBatch')}</label><input value={rollBatch} onChange={(e) => setRollBatch(e.target.value)} /></div>
          <div className="field"><label>{t('failThreshold')}</label><input value={failThreshold} onChange={(e) => setFailThreshold(e.target.value)} /></div>
          <div className="field"><label>{t('retryMax')}</label><input value={retryMax} onChange={(e) => setRetryMax(e.target.value)} /></div>
          <div className="field"><label>{t('timeoutSec')}</label><input value={timeoutSec} onChange={(e) => setTimeoutSec(e.target.value)} /></div>
        </div>
        <label className="check-row">
          <input type="checkbox" checked={dry} onChange={(e) => setDry(e.target.checked)} /> {t('dryRun')}
        </label>
        <div className="field"><label>{t('onFail')}</label>
          <select value={onFail} onChange={(e) => setOnFail(e.target.value as 'pause' | 'continue')}>
            <option value="pause">pause</option>
            <option value="continue">continue</option>
          </select>
        </div>
        {!!blockedTargets.length && (
          <p className="warn text-sm mb-2">
            May be blocked by op_mode: {blockedTargets.map((v) => `${v.name}(${v.op_mode})`).join(', ')}
            {!dry ? ' — live high-risk needs high_risk_allowed' : ''}
          </p>
        )}
        {type === 'script' && ids.length > 1 && scriptFlags.allow_batch === false && (
          <p className="warn text-sm mb-2">{t('scriptNoBatch')}</p>
        )}
        {type === 'script' && scriptFlags.allow_production === false && (vps.data ?? []).some((v) => ids.includes(v.id) && v.environment === 'production') && (
          <p className="warn text-sm mb-2">{t('scriptNoProd').replace('{names}', (vps.data ?? []).filter((v) => ids.includes(v.id) && v.environment === 'production').map((v) => v.name).join(', '))}</p>
        )}
        <button className="btn" onClick={() => create()} disabled={!ids.length || (type === 'script' && !scriptId)}>{t('createTask')}</button>
        {msg && <p className="muted text-sm mt-2">{msg}</p>}
      </div>
      <p className="stat-section-label">{t('taskList')}</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>ID</th><th>{t('type')}</th><th>{t('status')}</th><th>{t('mode')}</th><th>{t('risk')}</th><th>{t('when')}</th><th></th></tr></thead>
          <tbody>
            {taskRows.map((task) => (
              <tr key={task.id}>
                <td><Link to={`/tasks/${task.id}`}><code>{task.id.slice(0, 8)}</code></Link></td>
                <td className="text-sm">{task.type}</td>
                <td><span className={`badge ${taskStatusBadge(task.status)}`}>{task.status}</span></td>
                <td className="text-xs muted">{task.dry_run ? t('dryRun') : t('liveRun')}</td>
                <td><span className={`badge ${riskBadge(task.risk_level)}`}>{task.risk_level}</span></td>
                <td className="muted text-xs">{task.created_at ? new Date(task.created_at).toLocaleString() : '—'}</td>
                <td className="flex flex-wrap gap-1">
                  {task.status === 'waiting_approval' && (
                    <>
                      <button className="btn" onClick={() => decideTask(task.id, 'approve').then(() => list.refetch()).catch((ex) => setMsg((ex as Error).message))}>{t('approve')}</button>
                      <button className="btn secondary" onClick={() => { if (!confirm('Reject this task?')) return; decideTask(task.id, 'reject').then(() => list.refetch()).catch((ex) => setMsg((ex as Error).message)) }}>{t('reject')}</button>
                    </>
                  )}
                  {(task.status === 'failed' || task.status === 'partial' || task.status === 'timeout') && (
                    <button className="btn secondary" onClick={() => api(`/api/tasks/${task.id}/retry-failed`, { method: 'POST' }).then(() => list.refetch()).catch((ex) => setMsg((ex as Error).message))}>{t('retryFailed')}</button>
                  )}
                  <button className="btn secondary" onClick={() => exportTask(task.id)}>{t('export')}</button>
                  <button className="btn secondary" onClick={() => api(`/api/tasks/${task.id}/cancel`, { method: 'POST' }).then(() => list.refetch())}>{t('cancel')}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!list.isLoading && !taskRows.length && <p className="muted text-sm p-3">{t('emptyTasks')}</p>}
        {taskHasMore && (
          <button className="btn secondary mt-3" disabled={loadingMoreTasks} onClick={loadMoreTasks}>
            {loadingMoreTasks ? t('loading') : t('loadMore')}
          </button>
        )}
      </div>
    </Shell>
  )
}

const SCRIPT_CATEGORIES = [
  'misc', 'ops', 'security', 'maintenance', 'system-init', 'docker-install', 'backup', 'network', 'docker', 'probe',
]

function ScriptsPage() {
  const nav = useNavigate()
  const [statusFilter, setStatusFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [category, setCategory] = useState('misc')
  const qs = new URLSearchParams()
  if (statusFilter) qs.set('status', statusFilter)
  if (categoryFilter) qs.set('category', categoryFilter)
  const list = useQuery({
    queryKey: ['scripts', statusFilter, categoryFilter],
    queryFn: () => api<{
      id: number; name: string; status: string; risk_level: string; sha256: string
      source?: string; category?: string; version?: string; reviewed_by?: string
    }[]>(`/api/scripts?${qs.toString()}`),
  })
  const categories = useMemo(() => {
    const fromData = new Set(SCRIPT_CATEGORIES)
    for (const s of list.data ?? []) {
      if (s.category) fromData.add(s.category)
    }
    return [...fromData].sort()
  }, [list.data])
  const [name, setName] = useState('')
  const [content, setContent] = useState('#!/bin/sh\necho hello\n')
  const [paramsSchema, setParamsSchema] = useState('[]')
  const [healthcheck, setHealthcheck] = useState('')
  const [rollback, setRollback] = useState('')
  const [allowBatch, setAllowBatch] = useState(false)
  const [sensitive, setSensitive] = useState(false)
  const [allowProduction, setAllowProduction] = useState(false)
  const [importMsg, setImportMsg] = useState('')
  const create = async () => {
    await api('/api/scripts', {
      method: 'POST',
      body: JSON.stringify({
        name, content, risk_level: 'medium', category: category || 'misc',
        params_schema: paramsSchema || '[]', allow_batch: allowBatch, sensitive,
        allow_production: allowProduction,
        healthcheck_content: healthcheck || '',
        rollback_content: rollback || '',
      }),
    })
    list.refetch()
  }
  const importDraft = async (fileContent?: string, fileName?: string) => {
    const bodyContent = fileContent ?? content
    const bodyName = name || fileName?.replace(/\.[^.]+$/, '') || 'imported'
    if (!bodyContent.trim()) { setImportMsg('content required'); return }
    try {
      const r = await api<{ script: { id: number }; sha256: string; dangerous: string[]; note: string }>('/api/scripts/import', {
        method: 'POST',
        body: JSON.stringify({
          name: bodyName, content: bodyContent, source: 'import', category: category || 'imported',
        }),
      })
      setImportMsg(`Imported draft sha256=${r.sha256.slice(0, 16)}… ${r.dangerous?.length ? 'warnings: ' + r.dangerous.join(', ') : 'ok'} — ${r.note}`)
      list.refetch()
      if (r.script?.id) nav(`/scripts/${r.script.id}`)
    } catch (ex) { setImportMsg((ex as Error).message) }
  }
  const setScriptStatus = async (id: number, status: string) => {
    await api(`/api/scripts/${id}/review`, { method: 'POST', body: JSON.stringify({ status }) })
    list.refetch()
  }
  const scriptStatusBadge = (st: string) => {
    if (st === 'published' || st === 'approved') return 'ok'
    if (st === 'disabled' || st === 'archived') return 'err'
    if (st === 'review' || st === 'draft') return 'warn'
    return ''
  }
  const scriptRiskBadge = (r: string) => (r === 'high' || r === 'critical' ? 'err' : r === 'medium' ? 'warn' : '')

  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('scripts')}</h2>
        <select className="field" style={{ width: 140 }} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">{t('allStatus')}</option>
          <option value="draft">draft</option>
          <option value="review">review</option>
          <option value="approved">approved</option>
          <option value="published">published</option>
          <option value="disabled">disabled</option>
          <option value="archived">archived</option>
        </select>
        <select className="field" style={{ width: 160 }} value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)}>
          <option value="">{t('filterAll')}</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div className="card mb-4">
        <h3 className="form-section-title">{t('newScript')}</h3>
        <div className="field"><label>Name</label><input value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="field">
          <label>Category</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div className="field"><label>Content</label><textarea rows={6} value={content} onChange={(e) => setContent(e.target.value)} /></div>
        <div className="field"><label>Healthcheck (optional)</label><textarea rows={2} value={healthcheck} onChange={(e) => setHealthcheck(e.target.value)} placeholder="#!/bin/sh&#10;exit 0" /></div>
        <div className="field"><label>Rollback (optional)</label><textarea rows={2} value={rollback} onChange={(e) => setRollback(e.target.value)} /></div>
        <div className="field"><label>Params schema JSON</label><input value={paramsSchema} onChange={(e) => setParamsSchema(e.target.value)} placeholder='[{"name":"MSG","required":true}]' /></div>
        <label className="check-row">
          <input type="checkbox" checked={allowBatch} onChange={(e) => setAllowBatch(e.target.checked)} /> Allow batch (multi-host)
        </label>
        <label className="check-row">
          <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} /> Sensitive (redact task logs)
        </label>
        <label className="check-row">
          <input type="checkbox" checked={allowProduction} onChange={(e) => setAllowProduction(e.target.checked)} /> Allow on production hosts
        </label>
        <div className="settings-actions">
          <button className="btn" onClick={create}>Create draft</button>
          <button className="btn secondary" onClick={() => importDraft()}>Import as draft</button>
          <label className="btn secondary">
            Import file
            <input className="hidden" type="file" accept=".sh,.bash,.txt,text/*" onChange={async (e) => {
              const file = e.target.files?.[0]
              e.target.value = ''
              if (!file) return
              const text = await file.text()
              setContent(text)
              if (!name) setName(file.name.replace(/\.[^.]+$/, ''))
              await importDraft(text, file.name)
            }} />
          </label>
        </div>
        {importMsg && <p className="muted text-sm mt-2">{importMsg}</p>}
      </div>
      <p className="stat-section-label">{t('scriptCatalog')}</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>Name</th><th>Category</th><th>Ver</th><th>Status</th><th>Reviewer</th><th>Risk</th><th>SHA256</th><th></th></tr></thead>
          <tbody>
            {(list.data ?? []).map((s) => (
              <tr key={s.id}>
                <td><Link to={`/scripts/${s.id}`}>{s.name}</Link></td>
                <td className="muted text-sm">{s.category || '—'}</td>
                <td className="text-xs muted">{s.version || '—'}</td>
                <td><span className={`badge ${scriptStatusBadge(s.status)}`}>{s.status}</span></td>
                <td className="text-xs muted">{s.reviewed_by || '—'}</td>
                <td><span className={`badge ${scriptRiskBadge(s.risk_level)}`}>{s.risk_level}</span></td>
                <td className="text-xs muted"><code>{s.sha256.slice(0, 12)}</code></td>
                <td className="flex flex-wrap gap-1">
                  {s.status === 'draft' && <button className="btn secondary" onClick={() => setScriptStatus(s.id, 'review')}>{t('submitReview')}</button>}
                  {(s.status === 'draft' || s.status === 'review') && <button className="btn secondary" onClick={() => setScriptStatus(s.id, 'approved')}>{t('approve')}</button>}
                  {s.status === 'approved' && <button className="btn secondary" onClick={() => setScriptStatus(s.id, 'published')}>{t('publish')}</button>}
                  {(s.status === 'published' || s.status === 'approved') && <button className="btn secondary" onClick={() => setScriptStatus(s.id, 'disabled')}>{t('disable')}</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!list.isLoading && !(list.data ?? []).length && <p className="muted text-sm p-3">{t('emptyScripts')}</p>}
      </div>
    </Shell>
  )
}

function AlertsPage() {
  const initialOpen = typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('open') === '1'
  const [kindFilter, setKindFilter] = useState('')
  const [openOnly, setOpenOnly] = useState(initialOpen)
  const list = useQuery({
    queryKey: ['alerts', openOnly],
    queryFn: () => api<{
      id: number; kind: string; severity: string; message: string; created_at: string
      acknowledged?: boolean; vps_id?: number; target_kind?: string
    }[]>(`/api/alerts?limit=100${openOnly ? '&acknowledged=0' : ''}`),
  })
  const rows = (list.data ?? []).filter((a) => !kindFilter || a.kind === kindFilter)
  const kinds = useMemo(() => [...new Set((list.data ?? []).map((a) => a.kind))].sort(), [list.data])
  const open = rows.filter((a) => !a.acknowledged).length
  const targetLink = (a: { kind: string; vps_id?: number; target_kind?: string; message: string }) => {
    if (a.kind === 'login_failed' || a.kind === 'login_locked') {
      return <Link to="/settings#locks">{t('locks')}</Link>
    }
    if (a.kind === 'task_failed') {
      const m = a.message.match(/task\s+([0-9a-f-]{8,})/i)
      if (m) return <Link to={`/tasks/${m[1]}`}>{m[1].slice(0, 8)}</Link>
    }
    if (!a.vps_id) return '—'
    if (a.target_kind === 'website' || a.kind === 'website_expiry' || (a.kind === 'http_probe' && a.target_kind === 'website')) {
      return <Link to={`/websites?highlight=${a.vps_id}`}>site #{a.vps_id}</Link>
    }
    if (a.kind === 'expectation_gap') {
      return <Link to={`/vps/${a.vps_id}#expectations`}>#{a.vps_id}</Link>
    }
    if (a.kind === 'host_key_changed' || a.kind === 'cert_expiring' || a.kind === 'security_updates' || a.kind === 'need_reboot') {
      return <Link to={`/vps/${a.vps_id}#host-ops`}>#{a.vps_id}</Link>
    }
    if (a.kind === 'http_probe') {
      return <Link to={`/vps/${a.vps_id}`}>#{a.vps_id}</Link>
    }
    return <Link to={`/vps/${a.vps_id}`}>#{a.vps_id}</Link>
  }
  const sevBadge = (s: string) => {
    if (/crit|error|high/i.test(s)) return 'err'
    if (/warn|med/i.test(s)) return 'warn'
    return ''
  }
  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('alerts')}</h2>
        <select className="field" style={{ width: 180 }} value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
          <option value="">{t('filterAll')}</option>
          {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <label className="btn secondary">
          <input type="checkbox" className="mr-1" checked={openOnly} onChange={(e) => {
            const v = e.target.checked
            setOpenOnly(v)
            const sp = new URLSearchParams(window.location.search)
            if (v) sp.set('open', '1'); else sp.delete('open')
            const qstr = sp.toString()
            window.history.replaceState(null, '', qstr ? `/alerts?${qstr}` : '/alerts')
          }} />
          {t('openOnly')}
        </label>
        {open > 0 && (
          <button className="btn secondary" onClick={async () => {
            await api('/api/alerts/ack-all', { method: 'POST' })
            list.refetch()
          }}>{t('ackAll')} ({open})</button>
        )}
      </div>
      <div className="card">
        <table className="table">
          <thead><tr><th>{t('when')}</th><th>{t('severity')}</th><th>{t('kind')}</th><th>{t('target')}</th><th>{t('message')}</th><th></th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id} className={!a.acknowledged ? 'row-highlight' : undefined}>
                <td className="text-xs muted">{new Date(a.created_at).toLocaleString()}</td>
                <td><span className={`badge ${sevBadge(a.severity)}`}>{a.severity}</span></td>
                <td className="text-sm">{a.kind}</td>
                <td>{targetLink(a)}</td>
                <td className="text-sm">{a.message}</td>
                <td>{a.acknowledged ? <span className="badge ok">{t('acked')}</span> : <button className="btn secondary" onClick={async () => { await api(`/api/alerts/${a.id}/ack`, { method: 'POST' }); list.refetch() }}>{t('ack')}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="muted text-sm p-3">{t('emptyList')}</p>}
      </div>
    </Shell>
  )
}

function BackupsPage() {
  const list = useQuery({
    queryKey: ['backups'],
    queryFn: () => api<{
      id: number; name: string; path: string; kind?: string; sha256?: string
      encrypted?: boolean; created_at: string; vps_id?: number
    }[]>('/api/backups'),
  })
  const [msg, setMsg] = useState('')
  const run = async () => {
    try {
      const b = await api<{ name: string }>('/api/backup/panel', { method: 'POST' })
      setMsg(`Created ${b.name}`)
      list.refetch()
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const restore = async (id: number, name: string) => {
    if (!confirm(`Restore panel DB from ${name}? Writes vpshub.db.restored. Stop panel, then: vpshub restore-db -yes`)) return
    try {
      const r = await api<{ note?: string }>('/api/backup/restore', {
        method: 'POST', body: JSON.stringify({ id, confirm: true }),
      })
      setMsg((r.note || 'Wrote vpshub.db.restored') + ' — stop panel → vpshub restore-db -yes → start')
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const remove = async (id: number, name: string) => {
    if (!confirm(`Delete backup ${name}?`)) return
    try {
      await api(`/api/backups/${id}`, { method: 'DELETE', body: JSON.stringify({ confirm: true }) })
      setMsg(`Deleted ${name}`)
      list.refetch()
    } catch (ex) { setMsg((ex as Error).message) }
  }
  return (
    <Shell>
      <div className="page-toolbar">
        <h2 className="text-xl">{t('backups')}</h2>
        <button className="btn" onClick={run}>{t('createBackup')}</button>
      </div>
      {msg && <p className="muted mb-2 text-sm">{msg}</p>}
      <p className="muted text-sm mb-3">Newest 7 encrypted panel backups are kept. Restore writes vpshub.db.restored; stop the panel and run <code>vpshub restore-db -yes</code> to swap.</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>Name</th><th>Kind</th><th>VPS</th><th>SHA256</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {(list.data ?? []).map((b) => (
              <tr key={b.id}>
                <td>
                  {b.name}
                  {b.encrypted ? <span className="badge ok ml-1">enc</span> : null}
                </td>
                <td className="muted text-xs">{b.kind || '—'}</td>
                <td className="muted text-xs">
                  {b.vps_id ? <Link to={`/vps/${b.vps_id}`}>#{b.vps_id}</Link> : '—'}
                </td>
                <td className="muted text-xs">{b.sha256 ? <code>{b.sha256.slice(0, 12)}</code> : '—'}</td>
                <td className="text-xs muted">{new Date(b.created_at).toLocaleString()}</td>
                <td className="flex flex-wrap gap-1">
                  <button className="btn secondary" onClick={async () => {
                    const res = await fetch(`/api/backups/${b.id}/download`, { credentials: 'include' })
                    if (!res.ok) { setMsg('download failed'); return }
                    const blob = await res.blob()
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = b.name
                    a.click()
                    URL.revokeObjectURL(url)
                  }}>{t('download')}</button>
                  <button className="btn secondary" onClick={() => restore(b.id, b.name)}>{t('restore')}</button>
                  <button className="btn secondary" onClick={() => remove(b.id, b.name)}>{t('delete')}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  )
}

function SettingsPage() {
  type Tok = { id: number; name: string; scopes: string; expires_at?: string; revoked_at?: string; created_at: string }
  const feat = useQuery({
    queryKey: ['features'],
    queryFn: () => api<{
      webssh_enabled: boolean; sftp_enabled: boolean
      ssh_max_per_host?: number; ssh_max_output?: number
      task_max_conc?: number; task_prod_conc?: number; listen?: string
      ip_whitelist_on?: boolean; ip_whitelist_n?: number
      alert_webhook?: boolean; alert_telegram?: boolean; alert_smtp?: boolean
      vault_lock_ttl?: string
      version?: string
      ai_enabled?: boolean
    }>('/api/settings/features'),
  })
  const vp = useQuery({ queryKey: ['viewpw'], queryFn: () => api<{ configured: boolean }>('/api/view-password/status') })
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: () => api<Tok[]>('/api/tokens') })
  const sessions = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api<{ id: string; ip: string; user_agent: string; created_at: string; expires_at: string; current?: boolean }[]>('/api/sessions'),
  })
  const locks = useQuery({
    queryKey: ['locks'],
    queryFn: () => api<{
      locks: { key: string; until: string; reason?: string }[]
      recent_attempts: { id: number; username: string; ip: string; success: boolean; created_at: string }[]
    }>('/api/locks'),
  })
  const [oldP, setOldP] = useState('')
  const [newP, setNewP] = useState('')
  const [loginOld, setLoginOld] = useState('')
  const [loginNew, setLoginNew] = useState('')
  const [tokenName, setTokenName] = useState('ci')
  const [tokenHours, setTokenHours] = useState('')
  const [tokenFull, setTokenFull] = useState(false)
  const [tokenScopes, setTokenScopes] = useState<string[]>(['read'])
  const [token, setToken] = useState('')
  const [viewPw, setViewPw] = useState('')
  const [totpURL, setTotpURL] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [msg, setMsg] = useState('')
  const me = useMe()
  useEffect(() => {
    if (window.location.hash === '#locks') {
      document.getElementById('locks')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [])
  const rotate = async () => {
    try {
      const r = await api<{ recovery_key: string }>('/api/vault/rotate', {
        method: 'POST', body: JSON.stringify({ old_password: oldP, new_password: newP }),
      })
      setMsg('Rotated. New recovery key: ' + r.recovery_key)
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const changeLoginPassword = async () => {
    try {
      await api('/api/password', { method: 'POST', body: JSON.stringify({ old_password: loginOld, new_password: loginNew }) })
      setLoginOld(''); setLoginNew('')
      setMsg(t('passwordUpdated'))
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const createTok = async () => {
    try {
      const scopes = tokenFull ? ['*'] : tokenScopes
      if (!scopes.length) { setMsg('Select at least one scope'); return }
      const body: { name: string; expires_in_hours?: number; scopes?: string } = {
        name: tokenName,
        scopes: JSON.stringify(scopes),
      }
      const h = parseInt(tokenHours, 10)
      if (h > 0) body.expires_in_hours = h
      const r = await api<{ token: string }>('/api/tokens', { method: 'POST', body: JSON.stringify(body) })
      setToken(r.token)
      tokens.refetch()
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const toggleScope = (s: string) => {
    setTokenFull(false)
    setTokenScopes((cur) => cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s])
  }
  const parseScopes = (raw: string) => {
    try {
      const arr = JSON.parse(raw || '[]') as string[]
      return Array.isArray(arr) ? arr : []
    } catch { return [raw] }
  }
  const setupViewPw = async () => {
    try {
      await api('/api/view-password/setup', { method: 'POST', body: JSON.stringify({ password: viewPw, password_confirm: viewPw }) })
      setMsg('View password configured')
      vp.refetch()
    } catch (ex) { setMsg((ex as Error).message) }
  }
  return (
    <Shell>
      <h2 className="text-xl mb-3">{t('settings')}</h2>
      {msg && <p className="muted mb-3 text-sm break-all">{msg}</p>}
      <div className="settings-stack">
      <div className="card">
        <h3 className="form-section-title">{t('runtime')}</h3>
        <dl className="settings-kv">
          <dt>{t('version')}</dt><dd>{feat.data?.version ?? 'dev'} · {feat.data?.listen ?? '—'}</dd>
          <dt>AI</dt><dd>{feat.data?.ai_enabled ? <span className="badge ok">advise only</span> : <span className="muted text-sm">{t('aiDisabled')}</span>}</dd>
          <dt>WebSSH</dt><dd>{feat.data?.webssh_enabled ? <span className="badge ok">on</span> : <span className="badge">off</span>}</dd>
          <dt>SFTP</dt><dd>{feat.data?.sftp_enabled ? <span className="badge ok">on</span> : <span className="badge">off</span>}</dd>
          <dt>IP whitelist</dt><dd>{feat.data?.ip_whitelist_on ? `on (${feat.data.ip_whitelist_n})` : 'off'}</dd>
          <dt>Alerts</dt><dd className="text-sm">webhook {feat.data?.alert_webhook ? 'on' : 'off'} · telegram {feat.data?.alert_telegram ? 'on' : 'off'} · smtp {feat.data?.alert_smtp ? 'on' : 'off'}</dd>
          <dt>{t('vault')}</dt><dd>{feat.data?.vault_lock_ttl ?? '—'} · <span className={`badge ${me.data?.vault === 'unlocked' ? 'ok' : 'warn'}`}>{me.data?.vault ?? '—'}</span></dd>
          <dt>{t('viewPassword')}</dt><dd>{vp.data?.configured ? <span className="badge ok">configured</span> : <span className="badge warn">not set</span>} · <Link to="/vault">{t('vault')}</Link></dd>
          <dt>Limits</dt><dd className="muted text-sm">SSH max/host={feat.data?.ssh_max_per_host ?? '—'} · output {feat.data?.ssh_max_output ? Math.round(feat.data.ssh_max_output / 1024) + 'KB' : '—'} · task conc {feat.data?.task_max_conc ?? '—'}/{feat.data?.task_prod_conc ?? '—'}</dd>
          <dt>{t('opsDoc')}</dt><dd className="text-sm"><code>docs/ops-zh.md</code> · <code>/healthz</code></dd>
        </dl>
        <p className="muted text-xs mt-2">{t('featureConfigHint')}</p>
        <div className="settings-actions">
          <button className="btn secondary" onClick={() => api('/api/probes/run', { method: 'POST' }).then(() => setMsg('probes started'))}>Run probes now</button>
          <button className="btn secondary" onClick={() => api('/api/alerts/test/smtp', { method: 'POST' }).then(() => setMsg('smtp test sent')).catch((ex) => setMsg((ex as Error).message))}>SMTP test</button>
          <button className="btn secondary" onClick={() => api('/api/alerts/test/webhook', { method: 'POST' }).then(() => setMsg('webhook test sent')).catch((ex) => setMsg((ex as Error).message))}>Webhook test</button>
          <button className="btn secondary" onClick={() => api('/api/alerts/test/telegram', { method: 'POST' }).then(() => setMsg('telegram test sent')).catch((ex) => setMsg((ex as Error).message))}>Telegram test</button>
          <button className="btn secondary" onClick={async () => {
            if (!confirm('Revoke all sessions? You will need to log in again on every browser.')) return
            try {
              await api('/api/sessions/revoke-all', { method: 'POST' })
              setMsg('All sessions revoked')
              location.href = '/login'
            } catch (ex) { setMsg((ex as Error).message) }
          }}>Revoke all sessions</button>
        </div>
      </div>
      <div className="card">
        <h3 className="form-section-title">{t('activeSessions')}</h3>
        <table className="table">
          <thead><tr><th>IP</th><th>Created</th><th>UA</th><th></th></tr></thead>
          <tbody>
            {(sessions.data ?? []).map((s) => (
              <tr key={s.id}>
                <td>{s.ip || '—'}{s.current ? ' (this)' : ''}</td>
                <td className="text-xs muted">{new Date(s.created_at).toLocaleString()}</td>
                <td className="text-xs muted truncate max-w-xs">{s.user_agent || '—'}</td>
                <td>
                  <button className="btn secondary" onClick={async () => {
                    const r = await api<{ self?: boolean }>(`/api/sessions/${s.id}`, { method: 'DELETE' })
                    if (r.self) { location.href = '/login'; return }
                    sessions.refetch()
                  }}>Revoke</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!sessions.data?.length && <p className="muted text-sm">No sessions</p>}
      </div>
      <div className="card" id="locks">
        <div className="flex flex-wrap gap-2 items-center mb-2">
          <h3 className="form-section-title flex-1 !mb-0">{t('locks')}</h3>
          {(locks.data?.locks?.length ?? 0) > 0 && (
            <button className="btn secondary" onClick={async () => {
              if (!confirm('Clear all login locks?')) return
              try {
                const r = await api<{ cleared: number }>('/api/locks/clear-all', { method: 'POST', body: JSON.stringify({ confirm: true }) })
                locks.refetch()
                setMsg(`Cleared ${r.cleared} locks`)
              } catch (ex) { setMsg((ex as Error).message) }
            }}>{t('clearAllLocks')}</button>
          )}
        </div>
        <p className="muted text-sm mb-2">Active account/IP locks from failed logins. Clear to allow retry immediately.</p>
        <table className="table">
          <thead><tr><th>Key</th><th>Until</th><th>Reason</th><th></th></tr></thead>
          <tbody>
            {(locks.data?.locks ?? []).map((l) => (
              <tr key={l.key}>
                <td><code>{l.key}</code></td>
                <td className="text-xs">{new Date(l.until).toLocaleString()}</td>
                <td className="text-xs muted">{l.reason || '—'}</td>
                <td>
                  <button className="btn secondary" onClick={async () => {
                    await api('/api/locks/clear', { method: 'POST', body: JSON.stringify({ key: l.key }) })
                    locks.refetch()
                    setMsg('Lock cleared: ' + l.key)
                  }}>Clear</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!locks.data?.locks?.length && <p className="muted text-sm mb-3">No active locks</p>}
        <h4 className="text-sm mb-1 mt-3">{t('recentAttempts')}</h4>
        <table className="table">
          <thead><tr><th>User</th><th>IP</th><th>OK</th><th>When</th></tr></thead>
          <tbody>
            {(locks.data?.recent_attempts ?? []).slice(0, 15).map((a) => (
              <tr key={a.id}>
                <td>{a.username}</td>
                <td className="text-xs">{a.ip}</td>
                <td>{a.success ? <span className="badge ok">yes</span> : <span className="badge err">no</span>}</td>
                <td className="text-xs muted">{new Date(a.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3 className="form-section-title">{t('loginPassword')}</h3>
        <p className="muted text-sm mb-2">{t('changePasswordHint')}</p>
        <div className="field"><label>{t('currentPassword')}</label><input type="password" value={loginOld} onChange={(e) => setLoginOld(e.target.value)} /></div>
        <div className="field"><label>{t('newPassword')}</label><input type="password" value={loginNew} onChange={(e) => setLoginNew(e.target.value)} minLength={8} /></div>
        <button className="btn" onClick={changeLoginPassword} disabled={!loginOld || loginNew.length < 8}>{t('changePassword')}</button>
      </div>
      <div className="card">
        <h3 className="form-section-title">{t('viewPassword')}</h3>
        <p className="muted text-sm mb-2">Independent from login/vault. Required to reveal saved secrets. 5 failures wipe credential copies.</p>
        <div className="field"><label>{t('password')}</label><input type="password" value={viewPw} onChange={(e) => setViewPw(e.target.value)} /></div>
        <button className="btn" onClick={setupViewPw}>Setup / update</button>
      </div>
      <div className="card">
        <h3 className="form-section-title">TOTP</h3>
        <p className="muted text-sm mb-2">Status: {me.data?.totp_enabled ? <span className="badge ok">enabled</span> : <span className="badge warn">pending</span>}</p>
        <button className="btn secondary" onClick={async () => {
          try {
            const r = await api<{ totp_url: string; enabled: boolean }>('/api/totp/setup')
            setTotpURL(r.totp_url)
            setMsg(r.enabled ? 'TOTP already enabled — URL shown for re-scan if needed' : 'Scan URL then confirm code')
          } catch (ex) { setMsg((ex as Error).message) }
        }}>Show TOTP setup URL</button>
        {totpURL && <p className="text-xs break-all mt-2"><code>{totpURL}</code></p>}
        <div className="field mt-2"><label>Confirm code</label>
          <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="6 digits" /></div>
        <button className="btn" onClick={async () => {
          try {
            await api('/api/totp/enable', { method: 'POST', body: JSON.stringify({ code: totpCode }) })
            setMsg('TOTP enabled')
            setTotpCode('')
            me.refetch()
          } catch (ex) { setMsg((ex as Error).message) }
        }}>Enable / confirm TOTP</button>
      </div>
      <div className="card">
        <h3 className="form-section-title">{t('rotateMaster')}</h3>
        <div className="field"><label>Old</label><input type="password" value={oldP} onChange={(e) => setOldP(e.target.value)} /></div>
        <div className="field"><label>New</label><input type="password" value={newP} onChange={(e) => setNewP(e.target.value)} /></div>
        <button className="btn" onClick={rotate}>Rotate</button>
      </div>
      <div className="card">
        <h3 className="form-section-title">{t('tokens')}</h3>
        <p className="muted text-sm mb-2">Bearer token for automation. Combine read/write/admin, or full (*). Hash stored; plaintext shown once.</p>
        <ul className="muted text-xs mb-3 list-disc pl-5 space-y-0.5">
          <li>read — GET APIs (list VPS, tasks, metrics, audit…)</li>
          <li>write — create/update mutations (tasks, VPS, scripts, backups…)</li>
          <li>admin — vault, tokens, sessions, password, locks</li>
          <li>* — full access (all of the above)</li>
        </ul>
        <div className="field"><label>Name</label><input value={tokenName} onChange={(e) => setTokenName(e.target.value)} /></div>
        <div className="field">
          <label>Scopes</label>
          <label className="flex items-center gap-2 text-sm mb-1">
            <input type="checkbox" checked={tokenFull} onChange={(e) => {
              setTokenFull(e.target.checked)
              if (e.target.checked) setTokenScopes([])
            }} /> * (full)
          </label>
          {(['read', 'write', 'admin'] as const).map((s) => (
            <label key={s} className="flex items-center gap-2 text-sm mb-1">
              <input type="checkbox" disabled={tokenFull} checked={!tokenFull && tokenScopes.includes(s)} onChange={() => toggleScope(s)} /> {s}
            </label>
          ))}
        </div>
        <div className="field"><label>Expires in hours (optional)</label><input value={tokenHours} onChange={(e) => setTokenHours(e.target.value)} placeholder="blank = never" /></div>
        <button className="btn" onClick={createTok}>Create</button>
        {token && (
          <p className="mt-2 text-sm flex flex-wrap gap-2 items-center">
            Token (copy now): <code className="break-all">{token}</code>
            <button type="button" className="btn secondary" onClick={() => navigator.clipboard?.writeText(token).then(() => setMsg('Token copied')).catch(() => {})}>Copy</button>
          </p>
        )}
        <table className="table mt-3">
          <thead><tr><th>Name</th><th>Scopes</th><th>Created</th><th>Expires</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {(tokens.data ?? []).map((tok) => (
              <tr key={tok.id}>
                <td>{tok.name}</td>
                <td className="text-xs flex flex-wrap gap-1">
                  {parseScopes(tok.scopes).map((s) => <span key={s} className="badge">{s}</span>)}
                </td>
                <td className="text-xs">{tok.created_at}</td>
                <td className="text-xs">{tok.expires_at ?? '—'}</td>
                <td>{tok.revoked_at ? <span className="badge err">revoked</span> : <span className="badge ok">active</span>}</td>
                <td>{!tok.revoked_at && (
                  <button className="btn secondary" onClick={async () => {
                    await api(`/api/tokens/${tok.id}`, { method: 'DELETE' })
                    tokens.refetch()
                  }}>Revoke</button>
                )}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {msg && <p className="muted text-sm mt-2">{msg}</p>}
      </div>
      </div>
    </Shell>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/password" element={<PasswordPage />} />
          <Route path="/vault" element={<VaultPage />} />
          <Route path="/" element={<DashboardPage />} />
          <Route path="/vps" element={<VPSList />} />
          <Route path="/vps/new" element={<VPSNew />} />
          <Route path="/vps/:id" element={<VPSDetail />} />
          <Route path="/vps/:id/edit" element={<VPSEdit />} />
          <Route path="/providers" element={<ProvidersPage />} />
          <Route path="/websites" element={<WebsitesPage />} />
          <Route path="/matrix" element={<MatrixPage />} />
          <Route path="/templates" element={<TemplatesPage shell={(n) => <Shell>{n}</Shell>} />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/tasks/:id" element={<TaskDetailPage shell={(n) => <Shell>{n}</Shell>} />} />
          <Route path="/scripts" element={<ScriptsPage />} />
          <Route path="/scripts/:id" element={<ScriptDetailPage shell={(n) => <Shell>{n}</Shell>} />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alert-rules" element={<AlertRulesPage shell={(n) => <Shell>{n}</Shell>} />} />
          <Route path="/backups" element={<BackupsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
