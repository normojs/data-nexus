const AUTH_KEY = 'data-nexus-admin-auth'

export function useAdminAuth() {
  const config = useRuntimeConfig()
  const requiredPassword = computed(() => {
    const p = String(config.public.adminPassword || '').trim()
    return p.length > 0 ? p : null
  })
  const authRequired = computed(() => requiredPassword.value !== null)

  const authenticated = useState<boolean>('admin-authenticated', () => false)

  function hydrateFromStorage() {
    if (!import.meta.client) return
    if (!authRequired.value) {
      authenticated.value = true
      return
    }
    try {
      const raw = localStorage.getItem(AUTH_KEY)
      if (!raw) {
        authenticated.value = false
        return
      }
      const parsed = JSON.parse(raw) as { ok?: boolean; at?: number }
      // Session lasts 12 hours.
      const fresh = typeof parsed.at === 'number' && Date.now() - parsed.at < 12 * 60 * 60 * 1000
      authenticated.value = Boolean(parsed.ok && fresh)
      if (!authenticated.value) localStorage.removeItem(AUTH_KEY)
    }
    catch {
      authenticated.value = false
    }
  }

  function login(password: string): boolean {
    if (!authRequired.value) {
      authenticated.value = true
      return true
    }
    if (password === requiredPassword.value) {
      authenticated.value = true
      if (import.meta.client) {
        localStorage.setItem(AUTH_KEY, JSON.stringify({ ok: true, at: Date.now() }))
      }
      return true
    }
    return false
  }

  function logout() {
    authenticated.value = false
    if (import.meta.client) localStorage.removeItem(AUTH_KEY)
  }

  return {
    authRequired,
    authenticated,
    hydrateFromStorage,
    login,
    logout,
  }
}
