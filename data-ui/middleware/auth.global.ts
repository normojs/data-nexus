export default defineNuxtRouteMiddleware((to) => {
  // Public routes (login + OIDC callback + friendly auth error pages).
  if (
    to.path === '/login'
    || to.path === '/forbidden'
    || to.path.startsWith('/auth/')
  ) {
    return
  }

  const { authRequired, authenticated, hydrateFromStorage } = useAdminAuth()
  hydrateFromStorage()

  if (!authRequired.value) return
  if (!authenticated.value) {
    return navigateTo({ path: '/login', query: { next: to.fullPath } })
  }
})
