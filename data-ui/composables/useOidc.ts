/**
 * Browser OIDC Authorization Code + PKCE (public client).
 * Configure via NUXT_PUBLIC_OIDC_* env vars.
 */

type OidcDiscovery = {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

type StoredPkce = {
  state: string
  verifier: string
  next?: string
  at: number
}

const PKCE_KEY = 'data-nexus-oidc-pkce'
const AUTH_KEY = 'data-nexus-admin-auth'

function b64url(bytes: Uint8Array) {
  let str = ''
  bytes.forEach((b) => {
    str += String.fromCharCode(b)
  })
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function sha256(input: string) {
  const data = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return b64url(new Uint8Array(hash))
}

function randomString(len = 48) {
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  return b64url(bytes)
}

export function useOidc() {
  const config = useRuntimeConfig()

  const enabled = computed(() => {
    const issuer = String(config.public.oidcIssuer || '').trim()
    const clientId = String(config.public.oidcClientId || '').trim()
    return issuer.length > 0 && clientId.length > 0
  })

  const issuer = computed(() => String(config.public.oidcIssuer || '').replace(/\/$/, ''))
  const clientId = computed(() => String(config.public.oidcClientId || '').trim())
  const scopes = computed(() => String(config.public.oidcScopes || 'openid profile email').trim())
  const redirectUri = computed(() => {
    const configured = String(config.public.oidcRedirectUri || '').trim()
    if (configured) return configured
    if (import.meta.client) return `${window.location.origin}/auth/callback`
    return ''
  })

  async function discovery(): Promise<OidcDiscovery> {
    const url = `${issuer.value}/.well-known/openid-configuration`
    return await $fetch<OidcDiscovery>(url)
  }

  async function startLogin(next?: string) {
    if (!enabled.value) throw new Error('OIDC is not configured')
    const meta = await discovery()
    const state = randomString(24)
    const verifier = randomString(64)
    const challenge = await sha256(verifier)
    const payload: StoredPkce = { state, verifier, next, at: Date.now() }
    sessionStorage.setItem(PKCE_KEY, JSON.stringify(payload))

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId.value,
      redirect_uri: redirectUri.value,
      scope: scopes.value,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })
    window.location.assign(`${meta.authorization_endpoint}?${params.toString()}`)
  }

  async function handleCallback(query: Record<string, string | string[] | null | undefined>) {
    const code = String(query.code || '')
    const state = String(query.state || '')
    const err = query.error ? String(query.error) : ''
    if (err) throw new Error(String(query.error_description || err))
    if (!code || !state) throw new Error('Missing OIDC code/state')

    const raw = sessionStorage.getItem(PKCE_KEY)
    if (!raw) throw new Error('Missing PKCE session; restart login')
    const stored = JSON.parse(raw) as StoredPkce
    sessionStorage.removeItem(PKCE_KEY)
    if (stored.state !== state) throw new Error('OIDC state mismatch')
    if (Date.now() - stored.at > 10 * 60 * 1000) throw new Error('OIDC login timed out')

    const meta = await discovery()
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId.value,
      code,
      redirect_uri: redirectUri.value,
      code_verifier: stored.verifier,
    })
    const token = await $fetch<{ access_token?: string, id_token?: string, expires_in?: number }>(
      meta.token_endpoint,
      {
        method: 'POST',
        body,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      },
    )

    const session = {
      ok: true,
      method: 'oidc',
      at: Date.now(),
      access_token: token.access_token,
      id_token: token.id_token,
      expires_in: token.expires_in,
    }
    localStorage.setItem(AUTH_KEY, JSON.stringify(session))
    return stored.next || '/'
  }

  async function endSession() {
    if (!enabled.value || !import.meta.client) return
    try {
      const raw = localStorage.getItem(AUTH_KEY)
      const parsed = raw ? JSON.parse(raw) as { id_token?: string } : {}
      const meta = await discovery()
      if (meta.end_session_endpoint) {
        const params = new URLSearchParams({
          post_logout_redirect_uri: window.location.origin + '/login',
        })
        if (parsed.id_token) params.set('id_token_hint', parsed.id_token)
        window.location.assign(`${meta.end_session_endpoint}?${params.toString()}`)
        return
      }
    }
    catch {
      // fall through
    }
  }

  return {
    enabled,
    issuer,
    clientId,
    redirectUri,
    scopes,
    startLogin,
    handleCallback,
    endSession,
  }
}
