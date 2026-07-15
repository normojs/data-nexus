const AUTH_KEY = 'data-nexus-admin-auth'

type AuthSession = {
  ok?: boolean
  method?: 'password' | 'oidc' | 'break_glass'
  at?: number
  access_token?: string
  id_token?: string
  expires_in?: number
}

export function useAdminAuth() {
  const config = useRuntimeConfig()
  const api = useAdminApi()
  const { apiBase } = useAdminSettings()

  /** UI-local password (legacy / offline). Prefer gateway break-glass when API auth is on. */
  const localPassword = computed(() => {
    const p = String(config.public.adminPassword || '').trim()
    return p.length > 0 ? p : null
  })
  const oidcConfigured = computed(() => {
    const issuer = String(config.public.oidcIssuer || '').trim()
    const clientId = String(config.public.oidcClientId || '').trim()
    return issuer.length > 0 && clientId.length > 0
  })

  const apiAuthEnabled = useState<boolean>('admin-api-auth-enabled', () => false)
  const breakGlassLogin = useState<boolean>('admin-break-glass-login', () => false)

  const passwordEnabled = computed(
    () => localPassword.value !== null || breakGlassLogin.value,
  )
  const authRequired = computed(
    () => passwordEnabled.value || oidcConfigured.value || apiAuthEnabled.value,
  )

  const authenticated = useState<boolean>('admin-authenticated', () => false)
  const authMethod = useState<'password' | 'oidc' | 'break_glass' | null>(
    'admin-auth-method',
    () => null,
  )

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
      const maxAge = parsed.expires_in
        ? Math.min(parsed.expires_in * 1000, 12 * 60 * 60 * 1000)
        : 12 * 60 * 60 * 1000
      const fresh = typeof parsed.at === 'number' && Date.now() - parsed.at < maxAge
      // When API auth is on, password sessions must carry a token.
      const needsToken = apiAuthEnabled.value && parsed.method !== 'oidc'
      const hasToken = Boolean(parsed.access_token)
      authenticated.value = Boolean(parsed.ok && fresh && (!needsToken || hasToken))
      authMethod.value = authenticated.value ? (parsed.method || 'password') : null
      if (!authenticated.value) localStorage.removeItem(AUTH_KEY)
    }
    catch {
      authenticated.value = false
      authMethod.value = null
    }
  }

  async function refreshApiAuthFlags() {
    try {
      const cfg = await api.authConfig(apiBase.value)
      apiAuthEnabled.value = Boolean(cfg.enabled)
      breakGlassLogin.value = Boolean(cfg.break_glass_login)
    }
    catch {
      // Gateway unreachable: keep previous flags.
    }
  }

  /** Local-only password gate (no Admin API JWT). */
  function loginLocal(password: string): boolean {
    if (!localPassword.value) return false
    if (password !== localPassword.value) return false
    authenticated.value = true
    authMethod.value = 'password'
    if (import.meta.client) {
      localStorage.setItem(
        AUTH_KEY,
        JSON.stringify({ ok: true, method: 'password', at: Date.now() }),
      )
    }
    return true
  }

  /** Prefer gateway break-glass; fall back to local password when API auth is off. */
  async function login(password: string): Promise<boolean> {
    if (!authRequired.value) {
      authenticated.value = true
      return true
    }
    await refreshApiAuthFlags()
    if (breakGlassLogin.value) {
      try {
        const token = await api.login(password, apiBase.value)
        authenticated.value = true
        authMethod.value = 'break_glass'
        if (import.meta.client) {
          localStorage.setItem(
            AUTH_KEY,
            JSON.stringify({
              ok: true,
              method: 'break_glass',
              at: Date.now(),
              access_token: token.access_token,
              expires_in: token.expires_in,
            }),
          )
        }
        return true
      }
      catch {
        return false
      }
    }
    return loginLocal(password)
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
    passwordEnabled,
    oidcEnabled: oidcConfigured,
    apiAuthEnabled,
    breakGlassLogin,
    hydrateFromStorage,
    refreshApiAuthFlags,
    login,
    loginLocal,
    markOidcAuthenticated,
    logout,
  }
}
