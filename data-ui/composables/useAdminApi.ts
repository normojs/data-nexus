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
  decision?: string
  subject_id?: string
  service?: string
  outcome?: string
  message?: string
  rule?: string
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
    auditEvents: (params?: { decision?: string, subject_id?: string, service?: string, limit?: number }, base?: string) => {
      const q = new URLSearchParams()
      if (params?.decision) q.set('decision', params.decision)
      if (params?.subject_id) q.set('subject_id', params.subject_id)
      if (params?.service) q.set('service', params.service)
      if (params?.limit) q.set('limit', String(params.limit))
      const qs = q.toString()
      return getJson<{ events: AdminAuditEvent[] }>(`/admin/audit/events${qs ? `?${qs}` : ''}`, base)
    },
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
    /** Download portal result as CSV/NDJSON/JSON blob (B05). */
    portalExport: async (body: {
      service: string
      sql: string
      lease_id?: string
      subject_id?: string
      max_rows?: number
      format: 'csv' | 'ndjson' | 'json'
    }, base?: string) => {
      const path = '/admin/portal/query'
      try {
        return await $fetch<Blob>(`${normalizeBase(base)}${path}`, {
          method: 'POST',
          headers: {
            ...authHeaders(),
            'Content-Type': 'application/json',
            Accept: '*/*',
          },
          body: { ...body, download: true },
          responseType: 'blob',
        })
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
