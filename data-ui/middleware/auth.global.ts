export default defineNuxtRouteMiddleware((to) => {
  // Public routes.
  if (to.path === '/login' || to.path.startsWith('/auth/')) return

  const { authRequired, authenticated, hydrateFromStorage } = useAdminAuth()
  hydrateFromStorage()

  if (!authRequired.value) return
  if (!authenticated.value) {
    return navigateTo({ path: '/login', query: { next: to.fullPath } })
  }
})
