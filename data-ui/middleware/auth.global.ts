export default defineNuxtRouteMiddleware((to) => {
  // Login page is always public.
  if (to.path === '/login') return

  const { authRequired, authenticated, hydrateFromStorage } = useAdminAuth()
  hydrateFromStorage()

  if (!authRequired.value) return
  if (!authenticated.value) {
    return navigateTo({ path: '/login', query: { next: to.fullPath } })
  }
})
