import { asAdminApiAuthError, type AdminApiAuthError } from '~/utils/adminApiAuth'

export type { AdminApiAuthError }
export { asAdminApiAuthError }

export type AdminListener = {
  name: string
  listen_addr: string
  protocol: string
  service: string
  auth_policy?: string | null
}

export type AdminService = {
  name: string
  backend_protocol: string
  endpoints: string[]
  route_policy?: string | null
  translation_policy?: string | null
  plugin_policies?: string[]
}

export type AdminEndpoint = {
  name: string
  protocol: string
  address: string
  database?: string | null
  role?: string
  weight?: number
}

export type AdminPool = {
  name?: string
  capacity: number
  endpoints: Array<{
    endpoint: string
    configured?: boolean
    factory_registered?: boolean
    idle_connections?: number
    capacity?: number
  }>
}

export type AdminSession = {
  id: number
  listener: string
  peer_addr?: string | null
  frontend_protocol: string
  database?: string | null
}

export type AdminMe = {
  subject: string
  roles: string[]
  permissions: string[]
  auth_method: string
  auth_enabled: boolean
}

export type AdminAuthPublicConfig = {
  enabled: boolean
  mode: string
  public_metrics: boolean
  break_glass_login?: boolean
}

export type AdminLoginResponse = {
  access_token: string
  token_type: string
  expires_in: number
  roles: string[]
}

export type AdminAuditEvent = {
  event_id?: string
  ts_unix_ms?: number
  decision?: string
  subject_id?: string
  service?: string
  outcome?: string
  message?: string
  rule?: string
  listener?: string
  command_type?: string
  action?: string
  db_user?: string
  sql_fingerprint?: string
  /** F32: truncated SQL at L1/L2 (stripped at L0). */
  sql_text?: string | null
  tables?: string[]
  audit_level?: string
  /** B08: post-mask sample JSON (bounded; only when sample_enabled + L2). */
  sample_body?: string | null
  sample_ref?: string | null
  sample_row_count?: number | null
  sample_bytes?: number | null
  sample_truncated?: boolean
}

export type AdminAuditStats = {
  accepted?: number
  written?: number
  dropped?: number
  queue_capacity?: number
  priority_queue_capacity?: number
  priority_accepted?: number
  priority_dropped?: number
  queue_len?: number
  priority_queue_len?: number
  recent_len?: number
  rotated?: number
  pruned?: number
  index_enabled?: boolean
  index_rows?: number
  index_inserted?: number
  index_errors?: number
  index_pruned?: number
  installed?: boolean
}

export type AdminAuditEventsResponse = {
  events: AdminAuditEvent[]
  source?: string
  note?: string
  stats?: AdminAuditStats
}

export type AdminProject = {
  name: string
  environment: string
  service: string
  description?: string
}

export type AdminVaultLease = {
  lease_id: string
  project: string
  environment: string
  service: string
  endpoint: string
  protocol: string
  address: string
  database?: string | null
  username: string
  issued_at_unix_ms: number
  expires_at_unix_ms: number
  access_token: string
  revoked?: boolean
  revoked_at_unix_ms?: number | null
  revoked_by?: string | null
}

export type AdminTicketStatus = 'pending' | 'active' | 'rejected'

export type AdminTicket = {
  id: string
  ticket_type: string
  subject_id: string
  sql_fingerprint: string
  sql_sample?: string | null
  issued_at_unix_ms: number
  expires_at_unix_ms: number
  max_uses: number
  uses: number
  issued_by?: string | null
  note?: string | null
  dual_control?: boolean
  status: AdminTicketStatus
  approved_by?: string | null
  approved_at_unix_ms?: number | null
  rejected_by?: string | null
  reject_reason?: string | null
}

export type AdminIssueTicketRequest = {
  subject_id: string
  sql: string
  ticket_type?: string
  ttl_secs?: number
  max_uses?: number
  note?: string
  dual_control?: boolean
}

export type AdminCedarStatus = {
  installed?: boolean
  ready?: boolean
  epoch?: number
  source?: string
  files?: number
  policy_count?: number
  loaded_at_unix_ms?: number
  pdp_backend?: string
  cache_epoch_reload?: boolean
  feature?: string
  message?: string
}

/** UI04: read-only security policy snapshot from GET /admin/security-policies */
export type AdminSecurityRule = {
  name: string
  effect: string
  actions: string[]
  tables: string[]
  columns: string[]
  subjects: string[]
  row_filter?: string | null
}

export type AdminSecurityMaskRule = {
  name: string
  algorithm: string
  replace_with?: string
  prefix_len: number
  suffix_len: number
}

export type AdminSecurityColumnTag = {
  column: string
  tables: string[]
  subjects: string[]
  mask_rule: string
  label?: string
}

export type AdminSecurityHighRiskRule = {
  name: string
  kind: string
  ticket_type: string
  actions: string[]
  tables: string[]
  subjects: string[]
  message?: string
}

export type AdminSecurityTimeRule = {
  name: string
  effect: string
  outside: boolean
  days: string[]
  start: string
  end: string
  timezone: string
  actions: string[]
  subjects: string[]
}

export type AdminSecurityPolicies = {
  enabled: boolean
  fail_closed: boolean
  star_policy: string
  default_audit_level: string
  /** F32: max chars of sql_text at L1/L2. */
  sql_text_max_chars?: number
  pdp_backend: string
  pdp_policy_dir?: string | null
  rule_count: number
  rules: AdminSecurityRule[]
  mask_rules?: AdminSecurityMaskRule[]
  column_tags?: AdminSecurityColumnTag[]
  high_risk_rules?: AdminSecurityHighRiskRule[]
  time_rules?: AdminSecurityTimeRule[]
  watermark?: {
    enabled: boolean
    mode: string
    column: string
    has_static_token: boolean
  }
  streaming?: {
    window_rows: number
    max_rows?: number | null
    max_bytes?: number | null
    passthrough: boolean
  }
  /** B08: L2 result sample knobs (requires default_audit_level=L2 when enabled). */
  audit_sample?: {
    sample_enabled: boolean
    sample_max_rows: number
    sample_max_bytes: number
    sample_inline: boolean
    sample_prefix: string
  }
  /** H05: multi-instance state (paths only; encrypt keys never returned). */
  state?: {
    backend: string
    ticket_path: string
    vault_path: string
    policy_path: string
    policy_poll_ms: number
    ticket_encrypt_configured: boolean
    vault_encrypt_configured: boolean
  }
}

export type AdminCedarReloadInfo = {
  epoch: number
  source: string
  files: number
  policy_count: number
  loaded_at_unix_ms: number
  swapped: boolean
}

export type AdminPortalQueryResult = {
  columns: string[]
  rows: unknown[][]
  row_count: number
  truncated: boolean
  service: string
  decision: string
  message?: string | null
  /** A09: backend_window | chunked when streaming export/query path. */
  stream?: string | null
  window_rows?: number | null
}

const AUTH_KEY = 'data-nexus-admin-auth'

function normalizeBase(base?: string) {
  const config = useRuntimeConfig()
  const raw = base || String(config.public.adminApiBase || 'http://127.0.0.1:8082')
  return raw.replace(/\/$/, '')
}

/** Prefer gateway JWT / OIDC access_token from local session. */
function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (!import.meta.client) return headers
  try {
    const raw = localStorage.getItem(AUTH_KEY)
    if (!raw) return headers
    const parsed = JSON.parse(raw) as { access_token?: string, token?: string }
    const token = parsed.access_token || parsed.token
    if (token) headers.Authorization = `Bearer ${token}`
  }
  catch {
    // ignore
  }
  return headers
}

/**
 * Client-side navigation for Admin API 401/403.
 * - 401 → clear session and send to login
 * - 403 → forbidden page with human-readable reason
 */
export function handleAdminApiAuthError(err: unknown, path?: string): boolean {
  const authErr = asAdminApiAuthError(err, path)
  if (!authErr) return false
  if (!import.meta.client) return true

  if (authErr.kind === 'unauthorized') {
    try {
      localStorage.removeItem(AUTH_KEY)
    }
    catch {
      // ignore
    }
    const next = typeof window !== 'undefined'
      ? window.location.pathname + window.location.search
      : '/'
    navigateTo({
      path: '/login',
      query: {
        next,
        reason: 'session_expired',
      },
    })
    return true
  }

  navigateTo({
    path: '/forbidden',
    query: {
      reason: authErr.code || 'forbidden',
      message: authErr.message,
      path: path || '',
    },
  })
  return true
}

async function adminFetch<T>(path: string, opts: Record<string, unknown> = {}, base?: string): Promise<T> {
  try {
    return await $fetch<T>(`${normalizeBase(base)}${path}`, {
      ...opts,
      headers: {
        ...authHeaders(),
        ...((opts.headers as Record<string, string> | undefined) || {}),
      },
    })
  }
  catch (err) {
    // Login itself should not bounce to login/forbidden loops.
    if (path !== '/admin/auth/login' && path !== '/admin/auth/config') {
      handleAdminApiAuthError(err, path)
    }
    throw err
  }
}

async function getJson<T>(path: string, base?: string): Promise<T> {
  return adminFetch<T>(path, {}, base)
}

export function useAdminApi() {
  return {
    normalizeBase,
    authHeaders,
    asAdminApiAuthError,
    handleAdminApiAuthError,
    version: (base?: string) =>
      $fetch<string>(`${normalizeBase(base)}/version`, { responseType: 'text' }),
    healthz: (base?: string) =>
      $fetch(`${normalizeBase(base)}/healthz`, { responseType: 'text' })
        .then(() => true)
        .catch(() => false),
    authConfig: (base?: string) => getJson<AdminAuthPublicConfig>('/admin/auth/config', base),
    me: (base?: string) => getJson<AdminMe>('/admin/me', base),
    listeners: (base?: string) => getJson<AdminListener[]>('/admin/listeners', base),
    services: (base?: string) => getJson<AdminService[]>('/admin/services', base),
    endpoints: (base?: string) => getJson<AdminEndpoint[]>('/admin/endpoints', base),
    pools: (base?: string) =>
      getJson<AdminPool[] | AdminPool>('/admin/pools', base).then((v) =>
        Array.isArray(v) ? v : [v],
      ),
    sessions: (base?: string) =>
      getJson<AdminSession[]>('/admin/sessions', base).catch(() => [] as AdminSession[]),
    auditEvents: (params?: {
      decision?: string
      subject_id?: string
      service?: string
      event_id?: string
      audit_level?: string
      from_ms?: number
      to_ms?: number
      limit?: number
    }, base?: string) => {
      const q = new URLSearchParams()
      if (params?.decision) q.set('decision', params.decision)
      if (params?.subject_id) q.set('subject_id', params.subject_id)
      if (params?.service) q.set('service', params.service)
      if (params?.event_id) q.set('event_id', params.event_id)
      if (params?.audit_level) q.set('audit_level', params.audit_level)
      if (params?.from_ms != null) q.set('from_ms', String(params.from_ms))
      if (params?.to_ms != null) q.set('to_ms', String(params.to_ms))
      if (params?.limit) q.set('limit', String(params.limit))
      const qs = q.toString()
      return getJson<AdminAuditEventsResponse>(`/admin/audit/events${qs ? `?${qs}` : ''}`, base)
    },
    /** UI03: pipeline counters (B06/B07); also embedded on events response. */
    auditStats: (base?: string) => getJson<AdminAuditStats>('/admin/audit/stats', base),
    projects: (base?: string) => getJson<AdminProject[]>('/admin/projects', base),
    vaultLeases: (base?: string) => getJson<AdminVaultLease[]>('/admin/vault/leases', base),
    issueVaultLease: (body: { project: string, environment: string, ttl_secs?: number }, base?: string) =>
      adminFetch<AdminVaultLease>('/admin/vault/leases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      }, base),
    revokeVaultLease: (id: string, body?: { reason?: string }, base?: string) =>
      adminFetch<AdminVaultLease>(`/admin/vault/leases/${encodeURIComponent(id)}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body || {},
      }, base),
    renewVaultLease: (id: string, body?: { ttl_secs?: number }, base?: string) =>
      adminFetch<AdminVaultLease>(`/admin/vault/leases/${encodeURIComponent(id)}/renew`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body || {},
      }, base),
    pruneVaultLeases: (base?: string) =>
      adminFetch<{ removed: number }>('/admin/vault/leases/prune', {
        method: 'POST',
      }, base),
    // UI01: tickets
    tickets: (limit = 50, base?: string) =>
      getJson<{ tickets: AdminTicket[] }>(`/admin/tickets?limit=${limit}`, base)
        .then(r => r.tickets || []),
    issueTicket: (body: AdminIssueTicketRequest, base?: string) =>
      adminFetch<AdminTicket>('/admin/tickets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      }, base),
    approveTicket: (id: string, body?: { note?: string }, base?: string) =>
      adminFetch<AdminTicket>(`/admin/tickets/${encodeURIComponent(id)}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body || {},
      }, base),
    rejectTicket: (id: string, body?: { reason?: string }, base?: string) =>
      adminFetch<AdminTicket>(`/admin/tickets/${encodeURIComponent(id)}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body || {},
      }, base),
    revokeTicket: (id: string, body?: { reason?: string }, base?: string) =>
      adminFetch<AdminTicket>(`/admin/tickets/${encodeURIComponent(id)}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body || {},
      }, base),
    pruneTickets: (base?: string) =>
      adminFetch<{ removed?: number, pruned?: number }>('/admin/tickets/prune', {
        method: 'POST',
      }, base),
    // UI02: Cedar PDP status + reload
    cedarStatus: (base?: string) => getJson<AdminCedarStatus>('/admin/security/cedar', base),
    cedarReload: (base?: string) =>
      adminFetch<AdminCedarReloadInfo>('/admin/security/cedar/reload', {
        method: 'POST',
      }, base),
    // UI04: read-only security policy (Local PDP rules / mask / high-risk / time)
    securityPolicies: (base?: string) =>
      getJson<AdminSecurityPolicies>('/admin/security-policies', base),
    portalQuery: (body: {
      service: string
      sql: string
      lease_id?: string
      subject_id?: string
      max_rows?: number
      format?: 'json' | 'csv' | 'ndjson'
      download?: boolean
    }, base?: string) =>
      adminFetch<AdminPortalQueryResult>('/admin/portal/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      }, base),
    /**
     * Download portal result as CSV/NDJSON/JSON (B05/A09).
     * Returns blob plus optional `x-data-nexus-stream` header
     * (`backend_window` | `chunked`).
     */
    portalExport: async (body: {
      service: string
      sql: string
      lease_id?: string
      subject_id?: string
      max_rows?: number
      format: 'csv' | 'ndjson' | 'json'
    }, base?: string): Promise<{ blob: Blob, stream: string | null, contentType: string | null }> => {
      const path = '/admin/portal/query'
      try {
        const res = await $fetch.raw(`${normalizeBase(base)}${path}`, {
          method: 'POST',
          headers: {
            ...authHeaders(),
            'Content-Type': 'application/json',
            Accept: '*/*',
          },
          body: { ...body, download: true },
          responseType: 'blob',
        })
        const stream =
          res.headers.get('x-data-nexus-stream') ||
          res.headers.get('X-Data-Nexus-Stream') ||
          null
        const contentType = res.headers.get('content-type')
        const blob = res._data as Blob
        return { blob, stream, contentType }
      }
      catch (err) {
        handleAdminApiAuthError(err, path)
        throw err
      }
    },
    reload: (base?: string) =>
      adminFetch('/admin/reload', {
        method: 'POST',
      }, base),
    login: (password: string, base?: string) =>
      $fetch<AdminLoginResponse>(`${normalizeBase(base)}/admin/auth/login`, {
        method: 'POST',
        body: { password },
        headers: { Accept: 'application/json' },
      }),
  }
}
