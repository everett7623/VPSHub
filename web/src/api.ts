function csrfToken(): string {
  const m = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/)
  return m ? decodeURIComponent(m[1]) : ''
}

export function formatApiError(err: unknown): string {
  const e = err as Error & { code?: string; data?: { error?: string; vps?: string } }
  const code = e.code || e.data?.error || e.message
  if (code === 'vault_locked' || e.message === 'vault_locked') {
    return 'vault_locked'
  }
  return e.message || String(err)
}

let viewTokenCache: { token: string; expiresAt: number } | null = null

/** Unlock (or reuse) a view-password token valid for ~2 minutes. */
export async function unlockViewToken(password?: string): Promise<string> {
  if (viewTokenCache && viewTokenCache.expiresAt > Date.now() + 5_000) {
    return viewTokenCache.token
  }
  const pw = password ?? window.prompt('View password') ?? ''
  if (!pw) throw new Error('view password required')
  const r = await api<{ view_token: string; expires_in_sec?: number }>('/api/view-password/unlock', {
    method: 'POST', body: JSON.stringify({ password: pw }),
  })
  const ttl = (r.expires_in_sec ?? 120) * 1000
  viewTokenCache = { token: r.view_token, expiresAt: Date.now() + ttl }
  return r.view_token
}

export function parseParamsSchema(raw?: string): { name: string; required: boolean }[] {
  const s = (raw || '').trim()
  if (!s || s === '[]') return []
  try {
    const parsed = JSON.parse(s) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed.map((item) => {
      if (typeof item === 'string') return { name: item, required: false }
      const o = item as { name?: string; required?: boolean }
      return { name: String(o.name || ''), required: !!o.required }
    }).filter((d) => d.name)
  } catch {
    return []
  }
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const method = (init.method || 'GET').toUpperCase()
  if (method !== 'GET' && method !== 'HEAD') {
    const t = csrfToken()
    if (t) headers.set('X-CSRF-Token', t)
  }
  const res = await fetch(path, { ...init, headers, credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const body = data as { error?: string; vps?: string }
    let message = body.error || res.statusText
    if (body.error === 'op_mode_blocks') {
      message = body.vps
        ? `VPS "${body.vps}" blocks this change (op_mode)`
        : 'Operation blocked by VPS op_mode'
    }
    if (body.error === 'outside_maintenance_window') {
      message = body.vps
        ? `Outside maintenance window for VPS "${body.vps}"`
        : 'Outside maintenance window'
    }
    if (body.error === 'vault_locked' || res.status === 423) {
      message = 'vault_locked'
    }
    const err = new Error(message) as Error & {
      status: number
      data: unknown
      code?: string
    }
    err.status = res.status
    err.data = data
    if (body.error === 'vault_locked' || res.status === 423) err.code = 'vault_locked'
    throw err
  }
  return data as T
}

export type VPS = {
  id: number
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  auth_method: string
  provider?: string
  provider_id?: number
  region?: string
  group_name?: string
  environment: string
  op_mode: string
  status: string
  host_key_fp?: string
  host_key_pending?: string
  last_scan_at?: string
  last_connect_at?: string
  notes?: string
  tags: string
  expires_at?: string
  auto_renewal?: boolean
  renewal_cycle?: string
  currency?: string
  purchase_date?: string
  purchase_price?: number
  monthly_cost?: number
  server_type?: string
  panel_type?: string
  panel_url?: string
  panel_username?: string
  bandwidth?: string
  cpu_cores?: number
  ram_gb?: number
  disk_gb?: number
  ipv4?: string
  ipv6?: string
  jump_host_id?: number
  maintenance_windows?: string
  sftp_root?: string
  socks_proxy?: string
  http_probe_enabled?: boolean
  http_probe_url?: string
  http_probe_healthy?: boolean
  http_probe_last_at?: string
  http_probe_last_error?: string
  tcp_reachable?: boolean
  tcp_checked_at?: string
  deleted_at?: string
}

export type AuditEntry = {
  id: number
  actor: string
  ip: string
  action: string
  target_type: string
  target_id: string
  risk_level: string
  result: string
  detail?: string
  failure_reason?: string
  task_id?: string
  created_at: string
}

export type Provider = {
  id: number
  name: string
  website?: string
  contact?: string
  notes?: string
  has_private_notes: boolean
  server_count?: number
}

export type Website = {
  id: number
  name: string
  domain: string
  site_type: string
  vps_id?: number
  vps_name?: string
  status: string
  expiry_date?: string
  http_probe_enabled: boolean
  http_probe_healthy?: boolean
  http_probe_url?: string
  http_probe_last_at?: string
  http_probe_last_error?: string
  notes?: string
  panel_type?: string
  panel_url?: string
  panel_username?: string
  has_panel_password?: boolean
}
