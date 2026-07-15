const AUTH_KEY = 'data-nexus-admin-auth'

type AuthSession = {
  ok?: boolean
  method?: 'password' | 'oidc'
  at?: number
  access_token?: string
  id_token?: string
  expires_in?: number
}

export function useAdminAuth() {
  const config = useRuntimeConfig()
  const requiredPassword = computed(() => {
    const p = String(config.public.adminPassword || '').trim()
    return p.length > 0 ? p : null
  })
  const oidcConfigured = computed(() => {
    const issuer = String(config.public.oidcIssuer || '').trim()
    const clientId = String(config.public.oidcClientId || '').trim()
    return issuer.length > 0 && clientId.length > 0
  })
  const authRequired = computed(() => requiredPassword.value !== null || oidcConfigured.value)

  const authenticated = useState<boolean>('admin-authenticated', () => false)
  const authMethod = useState<'password' | 'oidc' | null>('admin-auth-method', () => null)

  function hydrateFromStorage() {
    if (!import.meta.client) return
    if (!authRequired.value) {
      authenticated.value = true
      authMethod.value = null
      return
    }
    try {
      const raw = localStorage.getItem(AUTH_KEY)
      if (!raw) {
        authenticated.value = false
        authMethod.value = null
        return
      }
      const parsed = JSON.parse(raw) as AuthSession
      const maxAge = parsed.method === 'oidc' && parsed.expires_in
        ? Math.min(parsed.expires_in * 1000, 12 * 60 * 60 * 1000)
        : 12 * 60 * 60 * 1000
      const fresh = typeof parsed.at === 'number' && Date.now() - parsed.at < maxAge
      authenticated.value = Boolean(parsed.ok && fresh)
      authMethod.value = authenticated.value ? (parsed.method || 'password') : null
      if (!authenticated.value) localStorage.removeItem(AUTH_KEY)
    }
    catch {
      authenticated.value = false
      authMethod.value = null
    }
  }

  function login(password: string): boolean {
    if (!authRequired.value) {
      authenticated.value = true
      return true
    }
    if (!requiredPassword.value) {
      // Only OIDC configured — password form is not valid.
      return false
    }
    if (password === requiredPassword.value) {
      authenticated.value = true
      authMethod.value = 'password'
      if (import.meta.client) {
        localStorage.setItem(AUTH_KEY, JSON.stringify({ ok: true, method: 'password', at: Date.now() }))
      }
      return true
    }
    return false
  }

  function markOidcAuthenticated() {
    authenticated.value = true
    authMethod.value = 'oidc'
  }

  async function logout() {
    const method = authMethod.value
    authenticated.value = false
    authMethod.value = null
    if (import.meta.client) localStorage.removeItem(AUTH_KEY)
    if (method === 'oidc') {
      try {
        const { endSession } = useOidc()
        await endSession()
      }
      catch {
        // ignore
      }
    }
  }

  return {
    authRequired,
    authenticated,
    authMethod,
    passwordEnabled: computed(() => requiredPassword.value !== null),
    oidcEnabled: oidcConfigured,
    hydrateFromStorage,
    login,
    markOidcAuthenticated,
    logout,
  }
}
