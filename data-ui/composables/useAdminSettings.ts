const API_BASE_KEY = 'data-nexus-admin-api-base'

export function useAdminSettings() {
  const config = useRuntimeConfig()
  const defaultBase = String(config.public.adminApiBase || 'http://127.0.0.1:8082')

  const apiBase = useState<string>('admin-api-base', () => defaultBase)

  function hydrate() {
    if (!import.meta.client) return
    const saved = localStorage.getItem(API_BASE_KEY)
    if (saved) apiBase.value = saved
  }

  function setApiBase(value: string) {
    apiBase.value = value.replace(/\/$/, '')
    if (import.meta.client) localStorage.setItem(API_BASE_KEY, apiBase.value)
  }

  return {
    apiBase,
    defaultBase,
    hydrate,
    setApiBase,
  }
}
