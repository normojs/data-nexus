<script setup lang="ts">
const route = useRoute()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()
const { authRequired, logout, hydrateFromStorage } = useAdminAuth()

onMounted(() => {
  hydrateSettings()
  hydrateFromStorage()
})

const links = [
  { to: '/', label: 'Overview' },
  { to: '/topology', label: 'Topology' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/settings', label: 'Settings' },
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

function onLogout() {
  logout()
  navigateTo('/login')
}
</script>

<template>
  <div class="admin-shell">
    <header class="admin-header">
      <div>
        <h1>Data Nexus Admin</h1>
        <div class="meta">
          API <span class="mono">{{ apiBase }}</span>
        </div>
      </div>
      <nav class="nav-links">
        <NuxtLink
          v-for="link in links"
          :key="link.to"
          :to="link.to"
          class="nav-link"
          :class="{ active: isActive(link.to) }"
        >
          {{ link.label }}
        </NuxtLink>
      </nav>
      <div class="admin-actions">
        <a
          class="btn"
          :href="`${apiBase}/metrics`"
          target="_blank"
          rel="noreferrer"
        >/metrics</a>
        <a
          class="btn"
          :href="`${apiBase}/admin`"
          target="_blank"
          rel="noreferrer"
        >embedded</a>
        <button
          v-if="authRequired"
          type="button"
          class="btn"
          @click="onLogout"
        >
          Logout
        </button>
      </div>
    </header>
    <main class="admin-main">
      <slot />
    </main>
  </div>
</template>
