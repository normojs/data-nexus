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

async function getJson<T>(path: string, base?: string): Promise<T> {
  return await $fetch<T>(`${normalizeBase(base)}${path}`, {
    headers: authHeaders(),
  })
}

export function useAdminApi() {
  return {
    normalizeBase,
    authHeaders,
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
    reload: (base?: string) =>
      $fetch(`${normalizeBase(base)}/admin/reload`, {
        method: 'POST',
        headers: authHeaders(),
      }),
    login: (password: string, base?: string) =>
      $fetch<AdminLoginResponse>(`${normalizeBase(base)}/admin/auth/login`, {
        method: 'POST',
        body: { password },
        headers: { Accept: 'application/json' },
      }),
  }
}
