// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-05-15',
  devtools: { enabled: true },
  // Static SPA for production packaging (nginx / CDN).
  ssr: false,
  css: ['~/assets/css/admin.css'],
  modules: [
    '@nuxt/eslint',
    '@vueuse/nuxt',
  ],
  runtimeConfig: {
    public: {
      // Gateway Admin API base URL (override with NUXT_PUBLIC_ADMIN_API_BASE)
      adminApiBase: process.env.NUXT_PUBLIC_ADMIN_API_BASE || 'http://127.0.0.1:8082',
      // Optional UI password gate (leave empty to disable password auth)
      adminPassword: process.env.NUXT_PUBLIC_ADMIN_PASSWORD || '',
      // Optional OIDC / SSO (authorization code + PKCE, public client)
      oidcIssuer: process.env.NUXT_PUBLIC_OIDC_ISSUER || '',
      oidcClientId: process.env.NUXT_PUBLIC_OIDC_CLIENT_ID || '',
      oidcRedirectUri: process.env.NUXT_PUBLIC_OIDC_REDIRECT_URI || '',
      oidcScopes: process.env.NUXT_PUBLIC_OIDC_SCOPES || 'openid profile email',
    },
  },
  nitro: {
    prerender: {
      routes: ['/', '/topology', '/sessions', '/settings', '/login', '/auth/callback'],
    },
  },
  app: {
    head: {
      title: 'Data Nexus Admin',
      meta: [
        { name: 'description', content: 'Data Nexus gateway administration UI' },
      ],
    },
  },
})
