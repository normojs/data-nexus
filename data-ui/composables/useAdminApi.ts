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

function normalizeBase(base?: string) {
  const config = useRuntimeConfig()
  const raw = base || String(config.public.adminApiBase || 'http://127.0.0.1:8082')
  return raw.replace(/\/$/, '')
}

async function getJson<T>(path: string, base?: string): Promise<T> {
  return await $fetch<T>(`${normalizeBase(base)}${path}`, {
    headers: { Accept: 'application/json' },
  })
}

export function useAdminApi() {
  return {
    normalizeBase,
    version: (base?: string) =>
      $fetch<string>(`${normalizeBase(base)}/version`, { responseType: 'text' }),
    healthz: (base?: string) =>
      $fetch(`${normalizeBase(base)}/healthz`, { responseType: 'text' })
        .then(() => true)
        .catch(() => false),
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
        headers: { Accept: 'application/json' },
      }),
  }
}
