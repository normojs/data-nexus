// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-05-15',
  devtools: { enabled: true },
  css: ['~/assets/css/admin.css'],
  modules: [
    '@nuxt/eslint',
    '@vueuse/nuxt',
  ],
  runtimeConfig: {
    public: {
      // Gateway Admin API base URL (override with NUXT_PUBLIC_ADMIN_API_BASE)
      adminApiBase: process.env.NUXT_PUBLIC_ADMIN_API_BASE || 'http://127.0.0.1:8082',
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
