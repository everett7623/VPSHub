import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { api } from './api'
import type { VPS } from './api'
import { t } from './i18n'

function csrf(): string {
  const m = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/)
  return m ? decodeURIComponent(m[1]) : ''
}

type MaintWin = { weekdays: number[]; start: string; end: string }

const WEEKDAYS = [
  { d: 0, label: 'Sun' }, { d: 1, label: 'Mon' }, { d: 2, label: 'Tue' },
  { d: 3, label: 'Wed' }, { d: 4, label: 'Thu' }, { d: 5, label: 'Fri' }, { d: 6, label: 'Sat' },
]

/** Visual editor for maintenance_windows JSON. Empty list = always allowed. */
export function MaintenanceWindowsEditor({ value, onChange }: { value: string; onChange: (json: string) => void }) {
  const parse = (raw: string): MaintWin[] => {
    try {
      const v = JSON.parse(raw || '[]')
      return Array.isArray(v) ? v.map((w) => ({
        weekdays: Array.isArray(w.weekdays) ? w.weekdays.map(Number) : [],
        start: w.start || '03:00',
        end: w.end || '05:00',
      })) : []
    } catch { return [] }
  }
  const [wins, setWins] = useState<MaintWin[]>(() => parse(value))
  useEffect(() => { setWins(parse(value)) }, [value])
  const emit = (next: MaintWin[]) => {
    setWins(next)
    onChange(JSON.stringify(next))
  }
  const toggleDay = (i: number, d: number) => {
    const next = wins.map((w, idx) => {
      if (idx !== i) return w
      const has = w.weekdays.includes(d)
      return { ...w, weekdays: has ? w.weekdays.filter((x) => x !== d) : [...w.weekdays, d].sort() }
    })
    emit(next)
  }
  return (
    <div className="space-y-2">
      <p className="muted text-xs">Empty = high-risk work always allowed. Otherwise only listed windows.</p>
      {wins.map((w, i) => (
        <div key={i} className="border border-[var(--border)] rounded p-2 text-sm">
          <div className="flex flex-wrap gap-2 mb-2">
            {WEEKDAYS.map(({ d, label }) => (
              <label key={d} className="flex items-center gap-1">
                <input type="checkbox" checked={w.weekdays.includes(d)} onChange={() => toggleDay(i, d)} />
                {label}
              </label>
            ))}
          </div>
          <div className="flex gap-2 items-center">
            <input type="time" value={w.start} onChange={(e) => {
              const next = [...wins]; next[i] = { ...w, start: e.target.value }; emit(next)
            }} />
            <span>–</span>
            <input type="time" value={w.end} onChange={(e) => {
              const next = [...wins]; next[i] = { ...w, end: e.target.value }; emit(next)
            }} />
            <button type="button" className="btn secondary" onClick={() => emit(wins.filter((_, j) => j !== i))}>Remove</button>
          </div>
        </div>
      ))}
      <button type="button" className="btn secondary" onClick={() => emit([...wins, { weekdays: [0], start: '03:00', end: '05:00' }])}>
        Add window
      </button>
    </div>
  )
}

export async function decideTask(
  id: string,
  action: 'approve' | 'reject',
  opts: { outside?: boolean; confirm_danger?: boolean; confirm_disable_password?: boolean } = {},
): Promise<void> {
  if (action === 'reject') {
    await api(`/api/tasks/${id}/reject`, { method: 'POST', body: '{}' })
    return
  }
  try {
    await api(`/api/tasks/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({
        confirm: true,
        confirm_outside_window: !!opts.outside,
        confirm_danger: !!opts.confirm_danger,
        confirm_disable_password: !!opts.confirm_disable_password,
      }),
    })
  } catch (ex) {
    const e = ex as Error & { status?: number; data?: { error?: string; vps?: string } }
    const vps = e.data?.vps ? ` (${e.data.vps})` : ''
    if (e.status === 409 && e.data?.error === 'outside_maintenance_window' && !opts.outside
      && confirm(`Outside maintenance window${vps}. Approve anyway?`)) {
      await decideTask(id, 'approve', { ...opts, outside: true })
      return
    }
    if (!opts.confirm_danger && (e.message.includes('confirm_danger') || e.data?.error?.includes('confirm_danger'))
      && confirm(`This task removes data${vps}. Approve anyway?`)) {
      await decideTask(id, 'approve', { ...opts, confirm_danger: true })
      return
    }
    if (!opts.confirm_disable_password && (e.message.includes('confirm_disable_password') || e.data?.error?.includes('confirm_disable_password'))
      && confirm(`Approve disabling SSH password login${vps}?`)) {
      await decideTask(id, 'approve', { ...opts, confirm_disable_password: true })
      return
    }
    throw e
  }
}

export function TaskDetailPage({ shell }: { shell: (n: ReactNode) => ReactNode }) {
  const { id } = useParams()
  const [data, setData] = useState<{
    task: {
      id: string; status: string; type: string; risk_level: string
      concurrency?: number; timeout_sec?: number; retry_max?: number
      roll_batch?: number; fail_threshold?: number; dry_run?: boolean
      payload?: string; created_by?: string; created_at?: string
    }
    items: { id: number; vps_id: number; status: string; attempt?: number; log_text: string; error?: string; result?: string }[]
  } | null>(null)
  const [vpsNames, setVpsNames] = useState<Record<number, string>>({})
  const [err, setErr] = useState('')
  useEffect(() => {
    api<{ task: typeof data extends null ? never : NonNullable<typeof data>['task']; items: NonNullable<typeof data>['items'] }>(`/api/tasks/${id}`)
      .then((res) => setData(res as NonNullable<typeof data>))
      .catch((ex) => setErr((ex as Error).message))
    api<VPS[]>('/api/vps').then((list) => {
      const m: Record<number, string> = {}
      for (const v of list ?? []) m[v.id] = v.name
      setVpsNames(m)
    }).catch(() => {})
    const es = new EventSource(`/api/tasks/${id}/stream`, { withCredentials: true })
    es.onmessage = (ev) => {
      try { setData(JSON.parse(ev.data)) } catch { /* ignore */ }
    }
    es.addEventListener('error', () => setErr((cur) => cur || 'stream closed'))
    es.addEventListener('done', () => es.close())
    return () => es.close()
  }, [id])
  const task = data?.task
  let onFail = 'pause'
  let payloadSummary = ''
  try {
    const p = JSON.parse(task?.payload || '{}') as {
      on_fail?: string; command?: string; script_id?: number; module?: string; package_manager?: string
    }
    if (p.on_fail === 'continue') onFail = 'continue'
    if (p.command) payloadSummary = `cmd: ${p.command}`
    else if (p.script_id) payloadSummary = `script #${p.script_id}`
    else if (p.module) payloadSummary = `module: ${p.module}`
    else if (p.package_manager) payloadSummary = `sysupgrade ${p.package_manager}`
  } catch { /* ignore */ }
  const act = async (fn: () => Promise<unknown>, label: string) => {
    setErr('')
    try { await fn() } catch (ex) { setErr(`${label}: ${(ex as Error).message}`) }
  }
  return shell(
    <div>
      <h2 className="text-xl mb-3">Task {id?.slice(0, 8)}</h2>
      <p className="mb-1">Status: {task?.status ?? '…'} · {task?.type} · {task?.risk_level}{task?.dry_run ? ` · ${t('dryRun')}` : ''}</p>
      {task && (
        <p className="muted text-sm mb-2">
          concurrency={task.concurrency ?? '—'} · timeout={task.timeout_sec ?? '—'}s · retry_max={task.retry_max ?? 0}
          {' · '}roll_batch={task.roll_batch ?? 0} · fail_threshold={task.fail_threshold ?? '—'}
          {' · '}on_fail={onFail}
          {task.created_by ? ` · by ${task.created_by}` : ''}
          {task.created_at ? ` · ${new Date(task.created_at).toLocaleString()}` : ''}
        </p>
      )}
      {payloadSummary && <p className="muted text-sm mb-2">{payloadSummary}</p>}
      <div className="flex flex-wrap gap-2 mb-3">
        {data?.task.status === 'waiting_approval' && (
          <>
            <button className="btn" onClick={() => { if (!id) return; act(() => decideTask(id, 'approve'), 'approve') }}>{t('approve')}</button>
            <button className="btn secondary" onClick={() => { if (!id || !confirm('Reject this task?')) return; act(() => decideTask(id, 'reject'), 'reject') }}>{t('reject')}</button>
          </>
        )}
        <button className="btn secondary" onClick={() => act(() => api(`/api/tasks/${id}/cancel`, { method: 'POST' }), 'cancel')}>{t('cancel')}</button>
        <button className="btn secondary" onClick={() => act(() => api(`/api/tasks/${id}/retry-failed`, { method: 'POST' }), 'retry')}>Retry failed</button>
        <Link className="btn secondary" to={`/audit?q=${encodeURIComponent(id || '')}`}>Audit</Link>
        <button className="btn secondary" onClick={async () => {
          try {
            const res = await fetch(`/api/tasks/${id}/export`, { credentials: 'include' })
            if (!res.ok) { setErr('export failed'); return }
            const blob = await res.blob()
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `task-${id}.json`
            a.click()
            URL.revokeObjectURL(url)
          } catch (ex) { setErr((ex as Error).message) }
        }}>Export</button>
      </div>
      {err && <p className="error text-sm mb-2">{err}</p>}
      {(data?.items ?? []).map((it) => (
        <div className="card mb-3" key={it.id}>
          <p>
            <Link to={`/vps/${it.vps_id}`}>{vpsNames[it.vps_id] || `VPS ${it.vps_id}`}</Link>
            {' · '}{it.status} · attempt {it.attempt ?? 0}
          </p>
          {it.error && <p className="error text-sm">{it.error}</p>}
          {it.result && !it.error && <p className="muted text-sm">{it.result}</p>}
          <pre className="text-xs whitespace-pre-wrap mt-2 max-h-64 overflow-auto">{it.log_text || '…'}</pre>
        </div>
      ))}
    </div>,
  )
}

export function ScriptDetailPage({ shell }: { shell: (n: ReactNode) => ReactNode }) {
  const { id } = useParams()
  type ScriptBody = {
    name: string; status: string; content: string; sha256: string; risk_level: string; version?: string
    params_schema?: string; allow_batch?: boolean; sensitive?: boolean; allow_production?: boolean
    healthcheck_content?: string; rollback_content?: string; category?: string
    source?: string; created_by?: string; reviewed_by?: string
  }
  type ScriptVer = {
    id: number; version: string; sha256: string; status_at_snapshot: string; note?: string
    created_by?: string; created_at: string
  }
  const [data, setData] = useState<{ script: ScriptBody; dangerous: string[] } | null>(null)
  const [versions, setVersions] = useState<ScriptVer[]>([])
  const [content, setContent] = useState('')
  const [healthcheck, setHealthcheck] = useState('')
  const [rollback, setRollback] = useState('')
  const [editMsg, setEditMsg] = useState('')
  const loadVersions = () => api<ScriptVer[]>(`/api/scripts/${id}/versions`).then(setVersions).catch(() => setVersions([]))
  useEffect(() => {
    api<{ script: ScriptBody; dangerous: string[] }>(`/api/scripts/${id}`).then((res) => {
      setData(res)
      setContent(res?.script?.content ?? '')
      setHealthcheck(res?.script?.healthcheck_content ?? '')
      setRollback(res?.script?.rollback_content ?? '')
    }).catch(() => setData(null))
    loadVersions()
  }, [id])
  const reload = async () => {
    const next = await api<{ script: ScriptBody; dangerous: string[] }>(`/api/scripts/${id}`)
    setData(next)
    setContent(next?.script?.content ?? '')
    setHealthcheck(next?.script?.healthcheck_content ?? '')
    setRollback(next?.script?.rollback_content ?? '')
    await loadVersions()
  }
  const setStatus = async (status: string) => {
    setEditMsg('')
    try {
      await api(`/api/scripts/${id}/review`, { method: 'POST', body: JSON.stringify({ status }) })
      await reload()
    } catch (ex) { setEditMsg((ex as Error).message) }
  }
  const setFlags = async (patch: { allow_batch?: boolean; sensitive?: boolean; allow_production?: boolean }) => {
    setEditMsg('')
    try {
      await api(`/api/scripts/${id}/flags`, { method: 'PATCH', body: JSON.stringify(patch) })
      await reload()
    } catch (ex) { setEditMsg((ex as Error).message) }
  }
  const saveBody = async () => {
    setEditMsg('')
    try {
      await api(`/api/scripts/${id}`, {
        method: 'PUT',
        body: JSON.stringify({
          content, healthcheck_content: healthcheck, rollback_content: rollback,
        }),
      })
      setEditMsg('Saved — status reset to draft for re-review')
      await reload()
    } catch (ex) { setEditMsg((ex as Error).message) }
  }
  const s = data?.script
  const [vpsId, setVpsId] = useState('')
  const [paramsJSON, setParamsJSON] = useState('{}')
  const [runMsg, setRunMsg] = useState('')
  const run = async (outside = false) => {
    setRunMsg('')
    if (!vpsId) { setRunMsg('select a VPS'); return }
    let params: Record<string, string> = {}
    try { params = JSON.parse(paramsJSON || '{}') } catch { setRunMsg('params must be JSON object'); return }
    try {
      const task = await api<{ id: string }>('/api/tasks', {
        method: 'POST',
        body: JSON.stringify({
          type: 'script', vps_ids: [Number(vpsId)], risk_level: 'high', confirm: true,
          confirm_outside_window: outside,
          payload: { script_id: Number(id), params },
        }),
      })
      setRunMsg(task.id)
    } catch (ex) {
      const e = ex as Error & { status?: number; data?: { error?: string; vps?: string } }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await run(true)
        return
      }
      if (e.status === 403 && (e.data?.error === 'op_mode_blocks' || e.message.includes('op_mode'))) {
        setRunMsg(e.data?.vps
          ? `Blocked: VPS "${e.data.vps}" op_mode rejects this change`
          : e.message)
        return
      }
      setRunMsg(e.message)
    }
  }
  return shell(
    <div>
      <h2 className="text-xl mb-2">{s?.name ?? 'Script'}</h2>
      <p className="muted mb-2">{s?.status} · v{s?.version ?? '—'} · {s?.risk_level} · {s?.sha256}</p>
      <p className="muted text-sm mb-2">
        {s?.category ? `category=${s.category} · ` : ''}
        {s?.source ? `source=${s.source} · ` : ''}
        {s?.created_by ? `by ${s.created_by}` : ''}
        {s?.reviewed_by ? ` · reviewed ${s.reviewed_by}` : ''}
      </p>
      <p className="muted text-sm mb-2">
        batch={s?.allow_batch ? 'yes' : 'no'} · sensitive={s?.sensitive ? 'yes' : 'no'} · production={s?.allow_production ? 'yes' : 'no'}
      </p>
      <div className="flex flex-wrap gap-2 mb-3">
        <button className="btn secondary" onClick={() => setFlags({ allow_batch: !s?.allow_batch })}>Toggle batch</button>
        <button className="btn secondary" onClick={() => setFlags({ sensitive: !s?.sensitive })}>Toggle sensitive</button>
        <button className="btn secondary" onClick={() => setFlags({ allow_production: !s?.allow_production })}>Toggle production</button>
      </div>
      {s?.params_schema && s.params_schema !== '[]' && (
        <p className="muted text-sm mb-2">Params schema: <code>{s.params_schema}</code> (passed as env, not shell concat)</p>
      )}
      {(data?.dangerous ?? []).length > 0 && <p className="error mb-2">Dangerous: {data?.dangerous.join(', ')}</p>}
      <div className="card mb-3">
        <div className="field"><label>{t('content')}</label><textarea rows={8} value={content} onChange={(e) => setContent(e.target.value)} /></div>
        <div className="field"><label>{t('healthcheck')}</label><textarea rows={3} value={healthcheck} onChange={(e) => setHealthcheck(e.target.value)} /></div>
        <div className="field"><label>{t('rollback')}</label><textarea rows={3} value={rollback} onChange={(e) => setRollback(e.target.value)} /></div>
        <button className="btn secondary" onClick={saveBody}>Save body (resets to draft)</button>
        {editMsg && <p className="muted text-sm mt-2">{editMsg}</p>}
      </div>
      <div className="flex gap-2 mb-4">
        {['review', 'approved', 'published', 'disabled', 'archived'].map((st) => (
          <button key={st} className="btn secondary" onClick={() => setStatus(st)}>{st}</button>
        ))}
      </div>
      {(s?.status === 'approved' || s?.status === 'published') && (
        <div className="card flex flex-wrap gap-2 items-end">
          <div className="field !mb-0"><label>{t('runOnVPS')}</label><VPSPicker value={vpsId} onChange={setVpsId} /></div>
          <div className="field !mb-0 flex-1 min-w-48"><label>{t('paramsJSON')}</label><input value={paramsJSON} onChange={(e) => setParamsJSON(e.target.value)} placeholder='{"MSG":"hello"}' /></div>
          <button className="btn" onClick={() => run(false)}>Run</button>
          {runMsg.includes('-') ? <Link to={`/tasks/${runMsg}`}>{runMsg.slice(0, 8)}</Link> : runMsg && <span className="error text-sm">{runMsg}</span>}
        </div>
      )}
      <div className="card mt-4">
        <h3 className="mb-2">{t('versionHistory')}</h3>
        <p className="muted text-sm mb-2">Snapshots on publish and before editing approved/published bodies. Restore loads into draft for re-review.</p>
        <table className="table">
          <thead><tr><th>Ver</th><th>Note</th><th>SHA</th><th>When</th><th></th></tr></thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.id}>
                <td>{v.version}</td>
                <td className="text-xs">{v.note || v.status_at_snapshot}</td>
                <td className="text-xs muted">{v.sha256.slice(0, 12)}…</td>
                <td className="text-xs muted">{new Date(v.created_at).toLocaleString()}</td>
                <td>
                  <button className="btn secondary" onClick={async () => {
                    if (!confirm(`Restore version ${v.version} into draft?`)) return
                    try {
                      await api(`/api/scripts/${id}/versions/${v.id}/restore`, {
                        method: 'POST', body: JSON.stringify({ confirm: true }),
                      })
                      setEditMsg(`Restored ${v.version} → draft`)
                      await reload()
                    } catch (ex) { setEditMsg((ex as Error).message) }
                  }}>Restore</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!versions.length && <p className="muted text-sm">{t('noSnapshots')}</p>}
      </div>
    </div>,
  )
}

const ALERT_KIND_HINT: Record<string, string> = {
  vps_expiry: 'days_before = alert N days before VPS expires',
  website_expiry: 'days_before = alert N days before website expires',
  cert_expiring: 'days_before = cert not_after within N days',
  disk_high: 'threshold = disk used % (e.g. 90)',
  mem_low: 'threshold = free mem % floor (e.g. 10)',
  load_high: 'threshold = load1 (e.g. 4)',
  security_updates: 'threshold = pending security package count',
  http_probe: 'fires when probe fails (threshold unused)',
  vps_offline: 'fires when status=offline (threshold unused)',
  login_locked: 'fires on account lock (threshold unused)',
  login_failed: 'fires on failed login burst (threshold unused)',
  expectation_gap: 'fires when expected service missing',
  task_failed: 'fires when task fails',
  host_key_changed: 'fires on host key mismatch',
  ssh_fail: 'fires on SSH connectivity fail',
  systemd_failed: 'fires when failed units present',
  docker_unhealthy: 'fires when unhealthy containers present',
}

export function AlertRulesPage({ shell }: { shell: (n: ReactNode) => ReactNode }) {
  type Rule = {
    id: number; name: string; kind: string; enabled: boolean; days_before: number
    threshold?: number | null; notify_channels?: string
  }
  const kinds = [
    'vps_expiry', 'website_expiry', 'http_probe', 'vps_offline',
    'disk_high', 'mem_low', 'load_high', 'cert_expiring', 'security_updates',
    'systemd_failed', 'docker_unhealthy', 'host_key_changed', 'ssh_fail', 'task_failed',
    'login_locked', 'login_failed', 'expectation_gap',
  ]
  const channelOpts = ['webhook', 'telegram', 'smtp']
  const [rules, setRules] = useState<Rule[]>([])
  const [name, setName] = useState('expiry')
  const [kind, setKind] = useState('vps_expiry')
  const [threshold, setThreshold] = useState('')
  const load = () => api<Rule[]>('/api/alert-rules').then((r) => setRules(r ?? []))
  useEffect(() => { load().catch(() => setRules([])) }, [])
  const save = async (r: Rule, patch: Partial<Rule>) => {
    await api(`/api/alert-rules/${r.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        name: r.name,
        kind: r.kind,
        enabled: patch.enabled ?? r.enabled,
        days_before: patch.days_before ?? r.days_before,
        threshold: patch.threshold !== undefined ? patch.threshold : r.threshold,
        notify_channels: patch.notify_channels ?? r.notify_channels ?? '["webhook","telegram","smtp"]',
      }),
    })
    load()
  }
  return shell(
    <div>
      <h2 className="text-xl mb-3">{t('alertRules')}</h2>
      <p className="muted text-sm mb-3">
        Disabled rules of a kind suppress that kind. Channels: webhook, telegram, smtp.
      </p>
      <div className="card mb-4">
        <h3 className="form-section-title">{t('newAlertRule')}</h3>
        <div className="flex flex-wrap gap-2 items-end">
          <div className="field !mb-0"><label>Name</label><input value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="field !mb-0"><label>Kind</label>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
          <div className="field !mb-0"><label>Threshold</label>
            <input style={{ width: 88 }} value={threshold} onChange={(e) => setThreshold(e.target.value)} placeholder="e.g. 90" /></div>
          <button className="btn" onClick={async () => {
            const body: Record<string, unknown> = {
              name, kind, days_before: 14, enabled: true, notify_channels: '["webhook","telegram","smtp"]',
            }
            const tv = parseFloat(threshold)
            if (!Number.isNaN(tv)) body.threshold = tv
            await api('/api/alert-rules', { method: 'POST', body: JSON.stringify(body) })
            load()
          }}>{t('create')}</button>
        </div>
        {ALERT_KIND_HINT[kind] && <p className="muted text-xs mt-2">{ALERT_KIND_HINT[kind]}</p>}
      </div>
      <p className="stat-section-label">{t('catalog')}</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>Name</th><th>Kind</th><th>Days</th><th>Threshold</th><th>Channels</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id} className={r.enabled ? undefined : 'is-quiet'}>
                <td>{r.name}</td>
                <td className="text-sm muted">{r.kind}</td>
                <td>
                  <input className="field !mb-0" style={{ width: 72 }} type="number" value={r.days_before}
                    onChange={(e) => setRules((cur) => cur.map((x) => x.id === r.id ? { ...x, days_before: Number(e.target.value) } : x))}
                    onBlur={(e) => save(r, { days_before: Number(e.target.value) })} />
                </td>
                <td>
                  <input className="field !mb-0" style={{ width: 72 }} type="number" value={r.threshold ?? ''}
                    onChange={(e) => setRules((cur) => cur.map((x) => x.id === r.id ? { ...x, threshold: e.target.value === '' ? null : Number(e.target.value) } : x))}
                    onBlur={(e) => save(r, { threshold: e.target.value === '' ? null : Number(e.target.value) })} />
                </td>
                <td>
                  <div className="flex flex-wrap gap-1 text-xs">
                    {channelOpts.map((ch) => {
                      let cur: string[] = []
                      try { cur = JSON.parse(r.notify_channels || '[]') } catch { cur = [] }
                      if (!Array.isArray(cur)) cur = []
                      const on = cur.includes(ch)
                      return (
                        <button key={ch} type="button" className={`btn secondary ${on ? '' : 'opacity-45'}`}
                          onClick={() => {
                            const next = on ? cur.filter((x) => x !== ch) : [...cur, ch]
                            const json = JSON.stringify(next)
                            setRules((rows) => rows.map((x) => x.id === r.id ? { ...x, notify_channels: json } : x))
                            save(r, { notify_channels: json })
                          }}>{ch}</button>
                      )
                    })}
                  </div>
                </td>
                <td>
                  <button className="btn secondary" onClick={() => save(r, { enabled: !r.enabled })}>
                    <span className={`badge ${r.enabled ? 'ok' : ''}`}>{r.enabled ? 'on' : 'off'}</span>
                  </button>
                </td>
                <td className="flex flex-wrap gap-1">
                  <button className="btn secondary" onClick={() => save(r, {})}>Save</button>
                  <button className="btn secondary" onClick={async () => { await api(`/api/alert-rules/${r.id}`, { method: 'DELETE' }); load() }}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rules.length && <p className="muted text-sm p-3">{t('emptyList')}</p>}
      </div>
    </div>,
  )
}

export function HostOps({ id, refresh = 0, opMode = 'normal_tasks' }: { id: string; refresh?: number; opMode?: string }) {
  const scan = useState<Record<string, unknown> | null>(null)
  const [payload, setPayload] = scan
  const [msg, setMsg] = useState('')
  const [logText, setLogText] = useState('')
  const [dir, setDir] = useState('/opt/app')
  const [volume, setVolume] = useState('')
  const [backupPaths, setBackupPaths] = useState<string[]>([])
  const [tplPaths, setTplPaths] = useState<string[]>([])
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [restoreStamp, setRestoreStamp] = useState('')
  const [restoreDry, setRestoreDry] = useState(true)
  const [stamps, setStamps] = useState<string[]>([])
  const readOnly = opMode === 'readonly_monitor' || opMode === 'no_changes'
  useEffect(() => {
    api<Record<string, unknown>>(`/api/vps/${id}/scan`).then(setPayload).catch(() => setPayload(null))
    api<{ paths: string[]; from_templates?: string[] }>(`/api/vps/${id}/config-backup-paths`)
      .then((r) => { setBackupPaths(r.paths ?? []); setTplPaths(r.from_templates ?? []) })
      .catch(() => { setBackupPaths([]); setTplPaths([]) })
  }, [id, refresh])
  useEffect(() => {
    if (!restoreOpen) return
    api<{ stamps: string[] }>(`/api/vps/${id}/config-stamps`)
      .then((r) => {
        setStamps(r.stamps ?? [])
        if (!restoreStamp && r.stamps?.length) setRestoreStamp(r.stamps[0])
      })
      .catch(() => setStamps([]))
  }, [id, restoreOpen])
  const confirmImpact = async (lookup: string, action: string, name: string) => {
    try {
      const imp = await api<{ depends_on: string[]; depended_on_by: string[] }>(`/api/services/impact?name=${encodeURIComponent(lookup)}`)
      const deps = (imp.depends_on ?? []).join(', ') || 'none'
      const affect = (imp.depended_on_by ?? []).join(', ') || 'none'
      if ((imp.depends_on?.length || imp.depended_on_by?.length) &&
        !confirm(`${action} ${name}\nDepends on: ${deps}\nMay affect: ${affect}\nContinue?`)) {
        return false
      }
    } catch { /* impact optional */ }
    return true
  }
  const act = async (kind: 'docker' | 'systemd', action: string, name: string, outside = false) => {
    if (readOnly) { setMsg(`Blocked by op_mode=${opMode}`); return }
    if (!outside) {
      const lookup = kind === 'docker' ? 'docker' : name.replace(/\.service$/, '')
      if (action === 'restart' || action === 'stop' || action === 'reload') {
        if (!(await confirmImpact(lookup, action, name))) return
      } else if (!confirm(`${action} ${name}?`)) {
        return
      }
    }
    try {
      const t = await api<{ id: string }>(`/api/vps/${id}/${kind}`, {
        method: 'POST',
        body: JSON.stringify({ action, name, confirm: true, confirm_outside_window: outside }),
      })
      setMsg(`task ${t.id}`)
    } catch (ex) {
      const e = ex as Error & { status?: number }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await act(kind, action, name, true)
        return
      }
      setMsg(e.message)
    }
  }
  const logs = async (kind: 'docker' | 'systemd', name: string) => {
    setLogText('')
    try {
      const res = await api<{ output: string }>(`/api/vps/${id}/logs`, {
        method: 'POST',
        body: JSON.stringify({ kind, name, lines: 200 }),
      })
      setLogText(res.output || '')
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const field = (k: string) => {
    const v = payload?.[k]
    return v == null ? '' : String(v)
  }
  const containers = field('containers').split(';').filter(Boolean)
  const units = field('systemd_running').split(';').filter(Boolean)
  const failed = field('systemd_failed').split(';').filter(Boolean)
  const updates = Number(field('security_updates') || 0)
  const certAt = Number(field('cert_not_after') || 0)
  const certDays = certAt > 0 ? Math.floor((certAt * 1000 - Date.now()) / 86400000) : null
  const needReboot = field('need_reboot') === 'true' || payload?.need_reboot === true
  const bad = (line: string) => /exited|unhealthy|restarting/i.test(line)
  const run = async (action: string, name: string, extra: Record<string, unknown> = {}, outside = false) => {
    if (readOnly) { setMsg(`Blocked by op_mode=${opMode}`); return }
    if (!outside) {
      if (action === 'restart' || action === 'stop') {
        if (!(await confirmImpact('docker', action, name))) return
      } else if (!extra.confirm_danger && !confirm(`${action} ${name}?`)) {
        return
      }
    }
    try {
      const t = await api<{ id: string }>(`/api/vps/${id}/docker`, {
        method: 'POST',
        body: JSON.stringify({ action, name, confirm: true, confirm_outside_window: outside, ...extra }),
      })
      setMsg(`task ${t.id}`)
    } catch (ex) {
      const e = ex as Error & { status?: number }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await run(action, name, extra, true)
        return
      }
      setMsg(e.message)
    }
  }
  const danger = async (action: string, name: string) => {
    if (readOnly) { setMsg(`Blocked by op_mode=${opMode}`); return }
    if (!(await confirmImpact('docker', action, name))) return
    if (!confirm(`${action} ${name}?`)) return
    if (!confirm('This removes data or stops a project. Continue?')) return
    await run(action, name, { confirm_danger: true }, false)
  }
  const backupCfg = async (outside = false) => {
    if (readOnly) { setMsg(`Blocked by op_mode=${opMode}`); return }
    const preview = backupPaths.length
      ? `Paths (${backupPaths.length}): ${backupPaths.slice(0, 8).join(', ')}${backupPaths.length > 8 ? '…' : ''}`
      : 'Archive whitelist config paths'
    if (!outside && !confirm(`${preview}\n\nArchive into /var/backups/vpshub/? This waits for a second approval.`)) return
    try {
      const t = await api<{ id: string }>(`/api/vps/${id}/config-backup`, {
        method: 'POST',
        body: JSON.stringify({ confirm: true, confirm_outside_window: outside }),
      })
      setMsg(`task ${t.id}`)
    } catch (ex) {
      const e = ex as Error & { status?: number }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await backupCfg(true)
        return
      }
      setMsg(e.message)
    }
  }
  const restoreCfg = async (outside = false) => {
    if (readOnly) { setMsg(`Blocked by op_mode=${opMode}`); return }
    const stamp = restoreStamp.trim()
    if (!/^\d{14}$/.test(stamp)) {
      setMsg('stamp must be 14 digits')
      return
    }
    const dry = restoreDry
    if (!outside && !dry && !confirm(`Restore config archives from /var/backups/vpshub/${stamp}/? This waits for a second approval.`)) return
    try {
      const task = await api<{ id: string }>(`/api/vps/${id}/config-restore`, {
        method: 'POST',
        body: JSON.stringify({ stamp, confirm: true, dry_run: dry, confirm_outside_window: outside }),
      })
      setMsg(`task ${task.id}`)
      setRestoreOpen(false)
    } catch (ex) {
      const e = ex as Error & { status?: number }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await restoreCfg(true)
        return
      }
      setMsg(e.message)
    }
  }
  return (
    <div className="grid md:grid-cols-2 gap-4 mt-4">
      <div className="card md:col-span-2 !py-2">
        <h3 className="text-sm">{t('hostOps')}</h3>
      </div>
      {readOnly && (
        <div className="card md:col-span-2">
          <p className="warn text-sm">{t('readOnlyMode')} (op_mode={opMode})</p>
        </div>
      )}
      {(needReboot || updates >= 1 || (certDays != null && certDays <= 14) || field('kernel') || field('loadavg')) && (
        <div className="card md:col-span-2">
          <h3 className="mb-2">{t('scanSummary')}</h3>
          <p className="text-sm muted mb-1">
            {field('kernel') ? `Kernel ${field('kernel')}` : ''}
            {field('loadavg') ? ` · load ${field('loadavg')}` : ''}
            {field('os_id') ? ` · ${field('os_id')} ${field('os_version')}` : ''}
          </p>
          {needReboot && <p className="warn text-sm">{t('rebootRequired')}</p>}
          {updates >= 1 && <p className="error text-sm">{t('securityUpdatesN').replace('{n}', String(updates))}</p>}
          {certDays != null && certDays <= 14 && <p className="error text-sm">{t('certExpiresIn').replace('{n}', String(certDays))}</p>}
          {(needReboot || updates >= 1) && (
            <div className="flex flex-wrap gap-2 mt-2 mb-1">
              <button className="btn secondary" disabled={readOnly} onClick={async () => {
                try {
                  const r = await api<{ id: string }>('/api/tasks', {
                    method: 'POST',
                    body: JSON.stringify({
                      type: 'sysupgrade', vps_ids: [Number(id)], dry_run: true, risk_level: 'low', confirm: false,
                      payload: { package_manager: 'apt', scope: 'security', reboot: false },
                    }),
                  })
                  setMsg(`task ${r.id}`)
                } catch (ex) { setMsg((ex as Error).message) }
              }}>{t('sysupgradeSecurity')}</button>
              <button className="btn secondary" disabled={readOnly} onClick={async () => {
                if (!confirm('Live security sysupgrade on this host? Prefer dry-run first.')) return
                try {
                  const r = await api<{ id: string }>('/api/tasks', {
                    method: 'POST',
                    body: JSON.stringify({
                      type: 'sysupgrade', vps_ids: [Number(id)], dry_run: false, risk_level: 'high', confirm: true,
                      payload: { package_manager: 'apt', scope: 'security', reboot: false },
                    }),
                  })
                  setMsg(`task ${r.id}`)
                } catch (ex) { setMsg((ex as Error).message) }
              }}>{t('sysupgradeLive')}</button>
            </div>
          )}
          <p className="muted text-xs mt-1">Config backup includes whitelist paths plus assigned template config_paths (must stay under whitelist roots).</p>
          {!!tplPaths.length && (
            <p className="muted text-xs">From templates: {tplPaths.join(', ')}</p>
          )}
        </div>
      )}
      <div className="card">
        <h3 className="mb-2">{t('containers')}</h3>
        <div className="flex gap-2 mb-2">
          <button className="btn secondary" disabled={readOnly} onClick={() => backupCfg(false)} title={backupPaths.slice(0, 12).join('\n')}>
            {t('backupConfigs')}{backupPaths.length ? ` (${backupPaths.length})` : ''}
          </button>
          <button className="btn secondary" disabled={readOnly} onClick={() => setRestoreOpen((v) => !v)}>{t('restoreConfigs')}</button>
        </div>
        {restoreOpen && (
          <div className="mb-3 p-2 border border-[var(--border)] rounded text-sm space-y-2">
            <div className="field !mb-0">
              <label>{t('restoreStamp')}</label>
              {!!stamps.length && (
                <select className="mb-1" value={stamps.includes(restoreStamp) ? restoreStamp : ''} onChange={(e) => setRestoreStamp(e.target.value)} disabled={readOnly}>
                  <option value="">— select —</option>
                  {stamps.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              )}
              <input value={restoreStamp} onChange={(e) => setRestoreStamp(e.target.value)} placeholder="20240101120000" disabled={readOnly} />
            </div>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={restoreDry} onChange={(e) => setRestoreDry(e.target.checked)} disabled={readOnly} />
              {t('dryRun')}
            </label>
            <div className="flex gap-2">
              <button className="btn" disabled={readOnly} onClick={() => restoreCfg(false)}>{t('restore')}</button>
              <button className="btn secondary" onClick={() => setRestoreOpen(false)}>{t('cancel')}</button>
            </div>
          </div>
        )}
        <div className="flex gap-2 mb-2">
          <button className="btn secondary" onClick={async () => {
            try {
              const res = await api<{ output: string }>(`/api/vps/${id}/docker/query`, { method: 'POST', body: JSON.stringify({ action: 'stats' }) })
              setLogText(res.output)
            } catch (ex) { setMsg((ex as Error).message) }
          }}>Stats</button>
          <button className="btn secondary" onClick={async () => {
            try {
              const res = await api<{ output: string }>(`/api/vps/${id}/docker/query`, { method: 'POST', body: JSON.stringify({ action: 'images' }) })
              setLogText(res.output)
            } catch (ex) { setMsg((ex as Error).message) }
          }}>Images</button>
          <button className="btn secondary" disabled={readOnly} onClick={() => danger('image_prune', '')}>Prune dangling</button>
        </div>
        {containers.map((line) => {
          const name = line.split('|')[0]
          return (
            <div key={line} className="flex gap-2 items-center text-sm py-1">
              <span className={`flex-1 truncate ${bad(line) ? 'error' : ''}`}>{line}</span>
              <button className="btn secondary" onClick={() => logs('docker', name)}>Logs</button>
              <button className="btn secondary" disabled={readOnly} onClick={() => act('docker', 'restart', name)}>Restart</button>
              <button className="btn secondary" disabled={readOnly} onClick={() => danger('rm', name)}>Delete</button>
            </div>
          )
        })}
        {!containers.length && <p className="muted text-sm">No containers in last scan.</p>}
        <div className="mt-3 flex flex-wrap gap-2 items-end">
          <div className="field !mb-0"><label>Compose dir</label><input value={dir} onChange={(e) => setDir(e.target.value)} disabled={readOnly} /></div>
          <button className="btn secondary" disabled={readOnly} onClick={() => run('compose_pull_up', dir, { dry_run: true })}>Config</button>
          <button className="btn secondary" disabled={readOnly} onClick={() => run('compose_pull_up', dir)}>Pull and up</button>
          <button className="btn secondary" disabled={readOnly} onClick={() => danger('compose_down', dir)}>Down</button>
        </div>
        <div className="mt-2 flex gap-2 items-end">
          <div className="field !mb-0"><label>Volume</label><input value={volume} onChange={(e) => setVolume(e.target.value)} disabled={readOnly} /></div>
          <button className="btn secondary" onClick={() => danger('volume_rm', volume)} disabled={readOnly || !volume}>Delete volume</button>
        </div>
      </div>
      <div className="card">
        <h3 className="mb-2">{t('systemd')}</h3>
        {!!failed.length && (
          <div className="mb-3">
            <p className="error text-sm mb-1">Failed</p>
            {failed.map((u) => (
              <div key={u} className="flex gap-2 items-center text-sm py-1">
                <span className="flex-1">{u}</span>
                <span className="muted text-xs">{field('systemd_fail_reason').split(';').find((r) => r.startsWith(u + '='))?.split('=')[1]}</span>
                <button className="btn secondary" disabled={readOnly} onClick={() => act('systemd', 'restart', u.endsWith('.service') ? u : u + '.service')}>Restart</button>
              </div>
            ))}
          </div>
        )}
        {units.slice(0, 30).map((u) => (
          <div key={u} className="flex gap-2 items-center text-sm py-1">
            <span className="flex-1">{u}</span>
            <button className="btn secondary" onClick={() => logs('systemd', u.endsWith('.service') ? u : u + '.service')}>Logs</button>
            <button className="btn secondary" disabled={readOnly} onClick={() => act('systemd', 'restart', u.endsWith('.service') ? u : u + '.service')}>Restart</button>
          </div>
        ))}
        {!units.length && <p className="muted text-sm">No units in last scan.</p>}
        {msg.startsWith('task ') && <p className="muted mt-2"><Link to={`/tasks/${msg.replace('task ', '')}`}>{msg}</Link></p>}
        {msg && !msg.startsWith('task ') && <p className="error text-sm mt-2">{msg}</p>}
      </div>
      {logText && <pre className="card md:col-span-2 text-xs whitespace-pre-wrap max-h-64 overflow-auto">{logText}</pre>}
    </div>
  )
}

export function WebSSH({ id, enabled }: { id: string; enabled: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const [scripts, setScripts] = useState<{ id: number; name: string; status: string }[]>([])
  const [scriptId, setScriptId] = useState('')
  const [snipMsg, setSnipMsg] = useState('')
  useEffect(() => {
    if (!enabled) return
    Promise.all([
      api<{ id: number; name: string; status: string }[]>('/api/scripts?status=approved'),
      api<{ id: number; name: string; status: string }[]>('/api/scripts?status=published'),
    ]).then(([a, p]) => {
      const map = new Map<number, { id: number; name: string; status: string }>()
      for (const s of [...(a ?? []), ...(p ?? [])]) map.set(s.id, s)
      setScripts([...map.values()])
    }).catch(() => setScripts([]))
  }, [enabled])
  if (!enabled) return null
  const sendSnippet = async () => {
    const sid = parseInt(scriptId, 10)
    if (!sid || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      setSnipMsg('connect first and pick an approved script')
      return
    }
    try {
      const res = await api<{ content: string; name: string }>(`/api/vps/${id}/webssh/snippet`, {
        method: 'POST', body: JSON.stringify({ script_id: sid }),
      })
      wsRef.current.send(res.content)
      if (!res.content.endsWith('\n')) wsRef.current.send('\n')
      setSnipMsg(`sent ${res.name}`)
    } catch (ex) { setSnipMsg((ex as Error).message) }
  }
  return (
    <div className="card mt-4">
      <h3 className="mb-2">WebSSH</h3>
      <button className="btn mb-2" onClick={() => {
        if (!ref.current) return
        ref.current.innerHTML = ''
        if (wsRef.current) { try { wsRef.current.close() } catch { /* ignore */ } }
        const term = new Terminal({ cursorBlink: true, fontSize: 13 })
        const fit = new FitAddon()
        term.loadAddon(fit)
        term.open(ref.current)
        fit.fit()
        const proto = location.protocol === 'https:' ? 'wss' : 'ws'
        const ws = new WebSocket(`${proto}://${location.host}/api/vps/${id}/webssh`)
        ws.binaryType = 'arraybuffer'
        wsRef.current = ws
        ws.onmessage = (ev) => {
          if (typeof ev.data === 'string') term.write(ev.data)
          else term.write(new Uint8Array(ev.data as ArrayBuffer))
        }
        term.onData((d) => { if (ws.readyState === WebSocket.OPEN) ws.send(d) })
      }}>Connect</button>
      <div className="flex gap-2 mb-2 items-end flex-wrap">
        <div className="field !mb-0"><label>Approved snippet</label>
          <select value={scriptId} onChange={(e) => setScriptId(e.target.value)}>
            <option value="">—</option>
            {scripts.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        </div>
        <button className="btn secondary" onClick={sendSnippet}>Send to terminal</button>
      </div>
      {snipMsg && <p className="muted text-sm mb-2">{snipMsg}</p>}
      <div ref={ref} className="h-80 bg-black" />
      <p className="muted text-xs mt-1">csrf {csrf() ? 'ok' : 'missing'} · only approved scripts · no passwords</p>
    </div>
  )
}

export function SFTPBrowser({ id }: { id: string }) {
  const [path, setPath] = useState('.')
  const [entries, setEntries] = useState<{ name: string; size: number; is_dir: boolean }[]>([])
  const [err, setErr] = useState('')
  const [textPath, setTextPath] = useState('')
  const [text, setText] = useState('')
  const [hosts, setHosts] = useState<VPS[]>([])
  const [targets, setTargets] = useState<number[]>([])
  const [distPath, setDistPath] = useState('')
  const [distMsg, setDistMsg] = useState('')
  const [hookId, setHookId] = useState('')
  const [deleteAfterHook, setDeleteAfterHook] = useState(false)
  useEffect(() => { api<VPS[]>('/api/vps').then(setHosts).catch(() => setHosts([])) }, [])
  const load = async (p = path) => {
    setErr('')
    try {
      const res = await api<{ entries: { name: string; size: number; is_dir: boolean }[] }>(`/api/vps/${id}/sftp?path=${encodeURIComponent(p)}`)
      setEntries(res.entries ?? [])
    } catch (ex) { setErr((ex as Error).message) }
  }
  return (
    <div className="card mt-4">
      <h3 className="mb-2">SFTP</h3>
      <div className="flex gap-2 mb-2">
        <input value={path} onChange={(e) => setPath(e.target.value)} />
        <button className="btn secondary" onClick={() => load()}>List</button>
      </div>
      {err && <p className="error text-sm">{err}</p>}
      <ul className="text-sm">
        {entries.map((e) => (
          <li key={e.name} className="flex gap-2 py-1">
            <button className="text-left flex-1" onClick={() => { if (e.is_dir) { const next = path === '.' ? e.name : `${path}/${e.name}`; setPath(next); load(next) } }}>
              {e.is_dir ? 'dir' : 'file'} {e.name}
            </button>
            {!e.is_dir && <button onClick={async () => {
              const p = path === '.' ? e.name : `${path}/${e.name}`
              try {
                const res = await api<{ content: string }>(`/api/vps/${id}/sftp/text?path=${encodeURIComponent(p)}`)
                setTextPath(p)
                setDistPath(p)
                setText(res.content)
              } catch (ex) { setErr((ex as Error).message) }
            }}>View</button>}
            {!e.is_dir && <a href={`/api/vps/${id}/sftp/download?path=${encodeURIComponent(path === '.' ? e.name : `${path}/${e.name}`)}`}>Download</a>}
          </li>
        ))}
      </ul>
      <div className="mt-2 flex flex-wrap gap-2 items-end">
        <div className="field !mb-0"><label>Hook script id</label><input value={hookId} onChange={(e) => setHookId(e.target.value)} placeholder="optional" /></div>
        <label className="text-sm flex gap-1 items-center"><input type="checkbox" checked={deleteAfterHook} onChange={(e) => setDeleteAfterHook(e.target.checked)} />Delete after hook</label>
      </div>
      <input className="mt-2" type="file" onChange={async (ev) => {
        const file = ev.target.files?.[0]
        if (!file) return
        if (hookId && !confirm(`Upload and run approved hook #${hookId}?`)) return
        const body = new FormData()
        body.append('file', file)
        body.append('path', path === '.' ? file.name : `${path}/${file.name}`)
        if (hookId) {
          body.append('hook_script_id', hookId)
          body.append('confirm', 'true')
          if (deleteAfterHook) body.append('delete_after_hook', 'true')
        }
        try {
          const res = await api<{ ok: boolean; sha256?: string; hook_error?: string; deleted_after_hook?: boolean }>(`/api/vps/${id}/sftp`, { method: 'POST', body })
          setErr(res.hook_error ? `uploaded; hook: ${res.hook_error}` : '')
          if (res.deleted_after_hook) setDistMsg('deleted after hook')
        } catch (ex) { setErr((ex as Error).message) }
        load()
      }} />
      {textPath && (
        <div className="mt-3">
          <p className="text-sm mb-1">{textPath}</p>
          <textarea rows={8} value={text} onChange={(e) => setText(e.target.value)} />
          <button className="btn mt-2" onClick={async () => {
            if (!confirm(`Write ${textPath}?`)) return
            try {
              await api(`/api/vps/${id}/sftp/text`, { method: 'PUT', body: JSON.stringify({ path: textPath, content: text, confirm: true }) })
              setErr('')
              load()
            } catch (ex) { setErr((ex as Error).message) }
          }}>Save text</button>
        </div>
      )}
      <div className="mt-3">
        <p className="text-sm mb-1">Distribute one file under each host sftp_root</p>
        <input className="mb-2" value={distPath} onChange={(e) => setDistPath(e.target.value)} placeholder="source path" />
        <select multiple className="min-h-24 mb-2" value={targets.map(String)} onChange={(e) => setTargets([...e.target.selectedOptions].map((o) => Number(o.value)))}>
          {hosts.filter((h) => String(h.id) !== id).map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
        </select>
        <button className="btn secondary" disabled={!distPath || !targets.length} onClick={async () => {
          if (!confirm(`Copy ${distPath} to ${targets.length} hosts?`)) return
          setDistMsg('')
          try {
            const res = await api<{ sha256: string }>(`/api/sftp/distribute`, {
              method: 'POST',
              body: JSON.stringify({
                source_vps_id: Number(id),
                source_path: distPath,
                dest_path: distPath,
                vps_ids: targets,
                confirm: true,
              }),
            })
            setDistMsg(`sha256 ${res.sha256}`)
          } catch (ex) { setDistMsg((ex as Error).message) }
        }}>Distribute</button>
        {distMsg && <p className="muted text-sm mt-1">{distMsg}</p>}
      </div>
    </div>
  )
}

type Template = {
  id: number; name: string; service_type: string; dependencies: string; risk_level: string
  config_paths?: string
}
type Gap = {
  template: string; service_type: string; actual: string; dependencies: string
  config_paths?: string; depends_on?: string[]; depended_on_by?: string[]; template_id?: number
}

export function TemplatesPage({ shell }: { shell: (n: ReactNode) => ReactNode }) {
  type Tpl = Template & { healthcheck?: string; config_paths?: string; usage_count?: number }
  const [rows, setRows] = useState<Tpl[]>([])
  const [editID, setEditID] = useState<number | null>(null)
  const [name, setName] = useState('')
  const [serviceType, setServiceType] = useState('')
  const [deps, setDeps] = useState('')
  const [paths, setPaths] = useState('')
  const [healthcheck, setHealthcheck] = useState('')
  const [risk, setRisk] = useState('medium')
  const [impact, setImpact] = useState<{ depends_on: string[]; depended_on_by: string[] } | null>(null)
  const [usageOf, setUsageOf] = useState<{ id: number; name: string; vps: { id: number; name: string }[] } | null>(null)
  const [err, setErr] = useState('')
  const toJSONArray = (raw: string) => JSON.stringify(raw.split(',').map((s) => s.trim()).filter(Boolean))
  const parseList = (_raw: string, fallback: string) => {
    try {
      const arr = JSON.parse(fallback || '[]') as string[]
      if (Array.isArray(arr)) return arr.join(', ')
    } catch { /* ignore */ }
    return ''
  }
  const load = () => api<Tpl[]>('/api/templates').then(setRows).catch((ex) => setErr((ex as Error).message))
  useEffect(() => { load() }, [])
  useEffect(() => {
    if (!serviceType) { setImpact(null); return }
    const q = new URLSearchParams({ name: serviceType, dependencies: toJSONArray(deps) })
    api<{ depends_on: string[]; depended_on_by: string[] }>(`/api/services/impact?${q}`)
      .then(setImpact).catch(() => setImpact(null))
  }, [serviceType, deps])
  const resetForm = () => {
    setEditID(null); setName(''); setServiceType(''); setDeps(''); setPaths(''); setHealthcheck(''); setRisk('medium'); setImpact(null)
  }
  const save = async () => {
    setErr('')
    const body = {
      name, service_type: serviceType, dependencies: toJSONArray(deps), risk_level: risk || 'medium',
      healthcheck: healthcheck || '', config_paths: toJSONArray(paths),
    }
    try {
      if (editID != null) {
        await api(`/api/templates/${editID}`, { method: 'PUT', body: JSON.stringify(body) })
      } else {
        await api('/api/templates', { method: 'POST', body: JSON.stringify(body) })
      }
      resetForm()
      load()
    } catch (ex) { setErr((ex as Error).message) }
  }
  const startEdit = (t: Tpl) => {
    setEditID(t.id)
    setName(t.name)
    setServiceType(t.service_type)
    try {
      const arr = JSON.parse(t.dependencies || '[]') as string[]
      setDeps(Array.isArray(arr) ? arr.join(', ') : t.dependencies)
    } catch { setDeps(t.dependencies || '') }
    try {
      const arr = JSON.parse(t.config_paths || '[]') as string[]
      setPaths(Array.isArray(arr) ? arr.join(', ') : (t.config_paths || ''))
    } catch { setPaths(t.config_paths || '') }
    setHealthcheck(t.healthcheck || '')
    setRisk(t.risk_level || 'medium')
  }
  const showUsage = async (tpl: Tpl) => {
    try {
      const vps = await api<{ id: number; name: string }[]>(`/api/templates/${tpl.id}/vps`)
      setUsageOf({ id: tpl.id, name: tpl.name, vps: vps ?? [] })
    } catch (ex) { setErr((ex as Error).message) }
  }
  const tplRiskBadge = (r?: string) => (r === 'high' || r === 'critical' ? 'err' : r === 'medium' ? 'warn' : '')
  return shell(
    <div>
      <h2 className="text-xl mb-3">{t('templates')}</h2>
      <div className="card mb-4">
        <h3 className="form-section-title">{editID != null ? 'Edit template' : t('newTemplate')}</h3>
        <div className="grid md:grid-cols-2 gap-3">
          <div className="field"><label>Name</label><input value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="field"><label>Service type</label><input value={serviceType} onChange={(e) => setServiceType(e.target.value)} placeholder="nginx" /></div>
          <div className="field"><label>Dependencies</label><input value={deps} onChange={(e) => setDeps(e.target.value)} placeholder="docker, certificates" /></div>
          <div className="field"><label>Config paths</label><input value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="/etc/nginx,/etc/nginx/sites-enabled" /></div>
          <div className="field"><label>Healthcheck hint</label><input value={healthcheck} onChange={(e) => setHealthcheck(e.target.value)} placeholder="systemctl is-active nginx" /></div>
          <div className="field"><label>Risk</label>
            <select value={risk} onChange={(e) => setRisk(e.target.value)}>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </div>
        </div>
        {impact && (
          <p className="muted text-xs mt-2">
            Registry impact — depends on: {impact.depends_on.join(', ') || 'none'}
            {' · '}may affect: {impact.depended_on_by.join(', ') || 'none'}
          </p>
        )}
        <div className="settings-actions">
          <button className="btn" onClick={save}>{editID != null ? 'Update' : 'Add'}</button>
          {editID != null && <button className="btn secondary" onClick={resetForm}>{t('cancel')}</button>}
        </div>
        {err && <p className="error text-sm mt-2">{err}</p>}
      </div>
      {usageOf && (
        <div className="card mb-4">
          <div className="flex gap-2 items-center mb-2">
            <h3 className="form-section-title flex-1 !mb-0">{t('usage')}: {usageOf.name}</h3>
            <button className="btn secondary" onClick={() => setUsageOf(null)}>{t('cancel')}</button>
          </div>
          {!usageOf.vps.length && <p className="muted text-sm">Not assigned to any VPS.</p>}
          <ul className="text-sm space-y-1">
            {usageOf.vps.map((v) => (
              <li key={v.id}><Link to={`/vps/${v.id}#expectations`}>{v.name}</Link></li>
            ))}
          </ul>
        </div>
      )}
      <p className="stat-section-label">{t('catalog')}</p>
      <div className="card">
        <table className="table">
          <thead><tr><th>Name</th><th>Service</th><th>Risk</th><th>{t('usage')}</th><th>Impact</th><th>Config paths</th><th>Healthcheck</th><th></th></tr></thead>
          <tbody>
            {rows.map((tpl) => (
              <tr key={tpl.id}>
                <td>{tpl.name}</td>
                <td className="text-sm">{tpl.service_type}</td>
                <td><span className={`badge ${tplRiskBadge(tpl.risk_level)}`}>{tpl.risk_level || '—'}</span></td>
                <td className="font-variant-numeric tabular-nums">
                  {(tpl.usage_count ?? 0) > 0
                    ? <button className="btn secondary" onClick={() => showUsage(tpl)}>{tpl.usage_count}</button>
                    : <span className="muted">0</span>}
                </td>
                <td className="muted text-xs">{tpl.dependencies}</td>
                <td className="muted text-xs">{parseList('', tpl.config_paths || '[]') || '—'}</td>
                <td className="muted text-xs">{tpl.healthcheck || '—'}</td>
                <td className="flex flex-wrap gap-1">
                  <button className="btn secondary" onClick={() => startEdit(tpl)}>Edit</button>
                  <button className="btn secondary" onClick={async () => {
                    if ((tpl.usage_count ?? 0) > 0 && !confirm(`Delete ${tpl.name}? Assigned to ${tpl.usage_count} VPS — expectations will be removed.`)) return
                    if (!(tpl.usage_count ?? 0) && !confirm(`Delete ${tpl.name}?`)) return
                    await api(`/api/templates/${tpl.id}`, { method: 'DELETE' }); load()
                  }}>{t('delete')}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="muted text-sm p-3">{t('emptyList')}</p>}
      </div>
    </div>,
  )
}

export function ChangeSnapshots({ id }: { id: string }) {
  const [changes, setChanges] = useState<{ field: string; before: string; after: string }[]>([])
  const [snaps, setSnaps] = useState<{ id: number; task_id?: string; phase: string; created_at: string }[]>([])
  const [selectedTask, setSelectedTask] = useState('')
  const [err, setErr] = useState('')
  const load = (taskID = '') => {
    const q = taskID ? `?task_id=${encodeURIComponent(taskID)}` : ''
    api<{ changes: { field: string; before: string; after: string }[]; snapshots: { id: number; task_id?: string; phase: string; created_at: string }[] }>(`/api/vps/${id}/changes${q}`)
      .then((res) => { setChanges(res.changes ?? []); setSnaps(res.snapshots ?? []); setErr('') })
      .catch((ex) => setErr((ex as Error).message))
  }
  useEffect(() => { load(selectedTask) }, [id, selectedTask])
  return (
    <div className="card mt-4">
      <h3 className="mb-2">{t('upgradeSnapshots')}</h3>
      <p className="muted text-sm mb-2">Before/after scan diffs from upgrade and sysupgrade tasks. Click a task row to compare that pair.</p>
      {err && <p className="error text-sm">{err}</p>}
      {!snaps.length && !err && <p className="muted text-sm">No snapshots yet — run an upgrade/sysupgrade task.</p>}
      {!!snaps.length && (
        <table className="table mb-3">
          <thead><tr><th>Phase</th><th>When</th><th>Task</th></tr></thead>
          <tbody>
            {snaps.map((s) => (
              <tr
                key={s.id}
                className={s.task_id && selectedTask === s.task_id ? 'warn' : undefined}
                style={s.task_id ? { cursor: 'pointer' } : undefined}
                onClick={() => { if (s.task_id) setSelectedTask((cur) => cur === s.task_id ? '' : s.task_id!) }}
              >
                <td>{s.phase}</td>
                <td className="text-xs muted">{s.created_at}</td>
                <td>{s.task_id ? <Link to={`/tasks/${s.task_id}`} onClick={(e) => e.stopPropagation()}>{s.task_id.slice(0, 8)}</Link> : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {selectedTask && <p className="muted text-xs mb-2">Diff for task {selectedTask.slice(0, 8)}… <button className="btn secondary" onClick={() => setSelectedTask('')}>Latest</button></p>}
      {!!changes.length && (
        <table className="table">
          <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
          <tbody>
            {changes.map((c) => (
              <tr key={c.field} className="warn"><td>{c.field}</td><td className="text-xs break-all">{c.before}</td><td className="text-xs break-all">{c.after}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {!!snaps.length && !changes.length && <p className="muted text-sm">Selected before/after pair has no field deltas.</p>}
    </div>
  )
}

function Sparkline({ values, maxHint }: { values: number[]; maxHint?: number }) {
  if (values.length < 2) return <span className="muted text-xs">—</span>
  const w = 120
  const h = 28
  const max = Math.max(maxHint ?? 0, ...values, 1)
  const min = Math.min(0, ...values)
  const span = max - min || 1
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w
    const y = h - ((v - min) / span) * (h - 2) - 1
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
  return (
    <svg width={w} height={h} className="block" aria-hidden>
      <polyline fill="none" stroke="var(--accent, #3b82f6)" strokeWidth="1.5" points={pts} />
    </svg>
  )
}

export function MetricsHistory({ id, refresh = 0 }: { id: string; refresh?: number }) {
  type Point = {
    created_at: string
    disk_used_pct?: number
    mem_used_pct?: number
    load_1?: number
    security_updates?: number
    cert_not_after?: number
  }
  const [points, setPoints] = useState<Point[]>([])
  const [limit, setLimit] = useState(50)
  const [err, setErr] = useState('')
  const load = () => {
    api<{ points: Point[] }>(`/api/vps/${id}/metrics?limit=${limit}`)
      .then((res) => { setPoints(res.points ?? []); setErr('') })
      .catch((ex) => setErr((ex as Error).message))
  }
  useEffect(() => { load() }, [id, refresh, limit])
  const fmt = (n?: number) => (n == null ? '—' : Number.isInteger(n) ? String(n) : n.toFixed(1))
  const chrono = [...points].reverse()
  const series = (key: 'disk_used_pct' | 'mem_used_pct' | 'load_1') =>
    chrono.map((p) => p[key]).filter((n): n is number => n != null)
  const latest = points[0]
  const prev = points[1]
  const delta = (a?: number, b?: number) => {
    if (a == null || b == null) return ''
    const d = a - b
    if (Math.abs(d) < 0.05) return ''
    return d > 0 ? `↑${d.toFixed(1)}` : `↓${Math.abs(d).toFixed(1)}`
  }
  return (
    <div className="card mt-4">
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <h3 className="flex-1">{t('metrics')}</h3>
        <select className="field !mb-0" style={{ width: 88 }} value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
        <button className="btn secondary" onClick={load}>Refresh</button>
      </div>
      {err && <p className="error text-sm">{err}</p>}
      {!points.length && !err && <p className="muted text-sm">No scan samples yet — run a scan on this VPS.</p>}
      {!!points.length && (
        <>
          <div className="grid md:grid-cols-3 gap-3 mb-3 text-sm">
            <div>
              <div className="muted text-xs mb-1">Disk % {delta(latest?.disk_used_pct, prev?.disk_used_pct)}</div>
              <Sparkline values={series('disk_used_pct')} maxHint={100} />
            </div>
            <div>
              <div className="muted text-xs mb-1">Mem % {delta(latest?.mem_used_pct, prev?.mem_used_pct)}</div>
              <Sparkline values={series('mem_used_pct')} maxHint={100} />
            </div>
            <div>
              <div className="muted text-xs mb-1">Load {delta(latest?.load_1, prev?.load_1)}</div>
              <Sparkline values={series('load_1')} />
            </div>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Time</th><th>Disk %</th><th>Mem %</th><th>Load</th><th>Sec updates</th><th>Cert exp</th>
              </tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.created_at}>
                  <td className="text-xs whitespace-nowrap">{p.created_at}</td>
                  <td>{fmt(p.disk_used_pct)}</td>
                  <td>{fmt(p.mem_used_pct)}</td>
                  <td>{fmt(p.load_1)}</td>
                  <td>{fmt(p.security_updates)}</td>
                  <td className="text-xs">{p.cert_not_after ? new Date(p.cert_not_after * 1000).toISOString().slice(0, 10) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

export function ScanDiff({ id, refresh = 0 }: { id: string; refresh?: number }) {
  const [changes, setChanges] = useState<{ field: string; before: string; after: string }[]>([])
  const [note, setNote] = useState('')
  const [beforeAt, setBeforeAt] = useState('')
  const [afterAt, setAfterAt] = useState('')
  useEffect(() => {
    api<{
      changes: { field: string; before: string; after: string }[]
      note?: string; before?: string; after?: string
    }>(`/api/vps/${id}/diff`)
      .then((res) => {
        setChanges(res.changes ?? [])
        setNote(res.note ?? '')
        setBeforeAt(res.before ? String(res.before) : '')
        setAfterAt(res.after ? String(res.after) : '')
      })
      .catch((ex) => setNote((ex as Error).message))
  }, [id, refresh])
  return (
    <div className="card mt-4">
      <h3 className="mb-2">{t('scanDiff')}</h3>
      {(beforeAt || afterAt) && (
        <p className="muted text-xs mb-2">
          {beforeAt ? new Date(beforeAt).toLocaleString() : '—'}
          {' → '}
          {afterAt ? new Date(afterAt).toLocaleString() : '—'}
        </p>
      )}
      {note && <p className="muted text-sm">{note === 'need two scans' ? t('needTwoScans') : note}</p>}
      {!changes.length && !note && <p className="muted text-sm">No field changes between last two scans.</p>}
      {!!changes.length && (
        <table className="table">
          <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
          <tbody>
            {changes.map((c) => (
              <tr key={c.field} className="warn">
                <td>{c.field}</td>
                <td className="text-xs">{c.before}</td>
                <td className="text-xs">{c.after}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

type CheckupFinding = {
  id: string
  area: string
  severity: string
  title: string
  detail?: string
  action?: string
}

const AREA_KEYS: Record<string, 'areaMonitor' | 'areaCleanup' | 'areaUpgrade' | 'areaOptimize' | 'areaSecurity'> = {
  monitor: 'areaMonitor',
  cleanup: 'areaCleanup',
  upgrade: 'areaUpgrade',
  optimize: 'areaOptimize',
  security: 'areaSecurity',
}

export function CheckupPanel({ id, refresh = 0, opMode = 'normal_tasks', onScanned }: {
  id: string
  refresh?: number
  opMode?: string
  onScanned?: () => void
}) {
  const [findings, setFindings] = useState<CheckupFinding[]>([])
  const [scannedAt, setScannedAt] = useState('')
  const [aiEnabled, setAiEnabled] = useState(false)
  const [msg, setMsg] = useState('')
  const [advice, setAdvice] = useState('')
  const [asking, setAsking] = useState(false)
  const readOnly = opMode === 'readonly_monitor' || opMode === 'no_changes'

  const load = async () => {
    const r = await api<{
      findings: CheckupFinding[]
      scanned_at?: string
      ai_enabled?: boolean
    }>(`/api/vps/${id}/checkup`)
    setFindings(r.findings ?? [])
    setScannedAt(r.scanned_at || '')
    setAiEnabled(!!r.ai_enabled)
  }

  useEffect(() => {
    load().catch((ex) => setMsg((ex as Error).message))
  }, [id, refresh])

  const findScript = async (name: string) => {
    const list = await api<{ id: number; name: string; status: string }[]>('/api/scripts')
    return (list ?? []).find((s) => s.name === name && (s.status === 'published' || s.status === 'approved'))
  }

  const runAction = async (action?: string) => {
    if (!action) return
    setMsg('')
    try {
      if (action === 'scan') {
        await api(`/api/vps/${id}/scan`, { method: 'POST' })
        setMsg('scan done')
        onScanned?.()
        await load()
        return
      }
      if (action === 'sysupgrade_security') {
        const tsk = await api<{ id: string }>('/api/tasks', {
          method: 'POST',
          body: JSON.stringify({
            type: 'sysupgrade', vps_ids: [Number(id)], dry_run: true, risk_level: 'low', confirm: false,
            payload: { package_manager: 'apt', scope: 'security', reboot: false },
          }),
        })
        setMsg(`task ${tsk.id}`)
        return
      }
      const sc = await findScript(action)
      if (!sc) {
        setMsg(`script "${action}" not published — review in Scripts`)
        return
      }
      if (readOnly) { setMsg(`Blocked by op_mode=${opMode}`); return }
      const tsk = await api<{ id: string }>('/api/tasks', {
        method: 'POST',
        body: JSON.stringify({
          type: 'script', vps_ids: [Number(id)], dry_run: true, risk_level: 'low', confirm: false,
          payload: { script_id: sc.id, params: {} },
        }),
      })
      setMsg(`task ${tsk.id}`)
    } catch (ex) { setMsg((ex as Error).message) }
  }

  const askAI = async () => {
    setAdvice('')
    setAsking(true)
    try {
      const r = await api<{ advice: string }>('/api/ai/advise', {
        method: 'POST',
        body: JSON.stringify({ vps_id: Number(id), prompt: '' }),
      })
      setAdvice(r.advice || '')
    } catch (ex) { setMsg((ex as Error).message) }
    finally { setAsking(false) }
  }

  const byArea = (area: string) => findings.filter((f) => f.area === area)
  const areas = ['monitor', 'cleanup', 'upgrade', 'optimize', 'security']

  return (
    <div className="card mt-4" id="checkup">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <h3 className="flex-1">{t('checkup')}</h3>
        <button className="btn secondary" onClick={() => runAction('scan')}>{t('runScan')}</button>
        <button className="btn secondary" disabled={!aiEnabled || asking} onClick={askAI}
          title={!aiEnabled ? t('aiDisabled') : undefined}>
          {asking ? t('aiAsking') : t('aiAdvise')}
        </button>
      </div>
      <p className="muted text-sm mb-2">
        {t('checkupHint')}
        {scannedAt ? ` · ${new Date(scannedAt).toLocaleString()}` : ''}
      </p>
      {!aiEnabled && <p className="muted text-xs mb-2">{t('aiDisabled')}</p>}
      <div className="grid md:grid-cols-2 gap-3">
        {areas.map((area) => {
          const rows = byArea(area)
          if (!rows.length) return null
          const key = AREA_KEYS[area]
          return (
            <div key={area} className="border-t border-[var(--border)] pt-2 first:border-t-0 first:pt-0 md:border md:border-[var(--border)] md:rounded md:p-2 md:pt-2">
              <h4 className="text-sm font-medium mb-1 text-[var(--muted)]">{key ? t(key) : area}</h4>
              <ul className="space-y-2 text-sm">
                {rows.map((f) => (
                  <li key={f.id}>
                    <span className={`badge ${f.severity === 'critical' ? 'err' : f.severity === 'warning' ? 'warn' : ''}`}>{f.severity}</span>{' '}
                    <span className="font-medium">{f.title}</span>
                    {f.detail ? <div className="muted text-xs mt-0.5">{f.detail}</div> : null}
                    {f.action && (
                      <button className="btn secondary mt-1" disabled={readOnly && f.action !== 'scan'}
                        onClick={() => runAction(f.action)}>{t('runAction')}: {f.action}</button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )
        })}
      </div>
      {!findings.length && <p className="muted text-sm">{t('emptyList')}</p>}
      {msg.startsWith('task ') && <p className="muted mt-2"><Link to={`/tasks/${msg.replace('task ', '')}`}>{msg}</Link></p>}
      {msg && !msg.startsWith('task ') && <p className="muted text-sm mt-2">{msg}</p>}
      {advice && (
        <pre className="mt-3 text-sm whitespace-pre-wrap max-h-80 overflow-auto border border-[var(--border)] rounded-[var(--radius)] p-3 bg-[var(--panel-soft)]">{advice}</pre>
      )}
    </div>
  )
}

export function ExpectationsPanel({ id }: { id: string }) {
  const [all, setAll] = useState<Template[]>([])
  const [picked, setPicked] = useState<number[]>([])
  const [gaps, setGaps] = useState<Gap[]>([])
  const [msg, setMsg] = useState('')
  const load = async () => {
    const [templates, exp] = await Promise.all([
      api<Template[]>('/api/templates'),
      api<{ assigned: Template[]; gaps: Gap[] }>(`/api/vps/${id}/expectations`),
    ])
    setAll(templates ?? [])
    setPicked((exp.assigned ?? []).map((t) => t.id))
    setGaps(exp.gaps ?? [])
  }
  useEffect(() => { load().catch((ex) => setMsg((ex as Error).message)) }, [id])
  const toggle = (tid: number) => setPicked((cur) => cur.includes(tid) ? cur.filter((x) => x !== tid) : [...cur, tid])
  const save = async () => {
    setMsg('')
    try {
      await api(`/api/vps/${id}/expectations`, { method: 'PUT', body: JSON.stringify({ template_ids: picked }) })
      await load()
    } catch (ex) { setMsg((ex as Error).message) }
  }
  const pathsLabel = (raw?: string) => {
    try {
      const arr = JSON.parse(raw || '[]') as string[]
      return Array.isArray(arr) && arr.length ? arr.join(', ') : ''
    } catch { return '' }
  }
  return (
    <div className="card mt-4" id="expectations">
      <h3 className="mb-2">{t('expectedServices')}</h3>
      {all.map((t) => (
        <label key={t.id} className="flex gap-2 text-sm py-1">
          <input type="checkbox" checked={picked.includes(t.id)} onChange={() => toggle(t.id)} />
          {t.name} <span className="muted">{t.service_type}</span>
          {pathsLabel(t.config_paths) && <span className="muted text-xs">· {pathsLabel(t.config_paths)}</span>}
        </label>
      ))}
      {!all.length && <p className="muted text-sm">No templates yet.</p>}
      <button className="btn secondary mt-2" onClick={save}>Save expectations</button>
      {gaps.map((g) => (
        <div key={g.template} className="text-sm mt-2">
          <p className="error">{g.template}: {g.actual}</p>
          <p className="muted text-xs">
            Depends on: {(g.depends_on?.length ? g.depends_on : []).join(', ') || '—'}
            {' · '}May affect: {(g.depended_on_by?.length ? g.depended_on_by : []).join(', ') || '—'}
          </p>
          {pathsLabel(g.config_paths) && <p className="muted text-xs">Config paths: {pathsLabel(g.config_paths)}</p>}
        </div>
      ))}
      {msg && <p className="error text-sm">{msg}</p>}
    </div>
  )
}

export function DisablePasswordButton({ id }: { id: string }) {
  const [msg, setMsg] = useState('')
  const run = async (outside = false) => {
    if (!outside) {
      if (!confirm('Disable SSH password login on this host?')) return
      if (!confirm('sshd_config will be backed up, then PasswordAuthentication will be set to no. Continue?')) return
    }
    try {
      const t = await api<{ id: string }>(`/api/vps/${id}/sshd/disable-password`, {
        method: 'POST',
        body: JSON.stringify({ confirm: true, confirm_disable_password: true, confirm_outside_window: outside }),
      })
      setMsg(t.id)
    } catch (ex) {
      const e = ex as Error & { status?: number }
      if (e.status === 409 && !outside && confirm('Outside maintenance window. Run anyway?')) {
        await run(true)
        return
      }
      setMsg(e.message)
    }
  }
  return (
    <span className="inline-flex items-center gap-2">
      <button className="btn secondary" onClick={() => run(false)}>Disable SSH password</button>
      {msg.includes('-') ? <Link className="text-sm" to={`/tasks/${msg}`}>{msg.slice(0, 8)}</Link> : msg && <span className="error text-sm">{msg}</span>}
    </span>
  )
}

export function VPSPicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [list, setList] = useState<VPS[]>([])
  useEffect(() => { api<VPS[]>('/api/vps').then(setList).catch(() => setList([])) }, [])
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">none</option>
      {list.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
    </select>
  )
}
