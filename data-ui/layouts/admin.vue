<script setup lang="ts">
const route = useRoute()
const api = useAdminApi()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()
const { authRequired, logout, hydrateFromStorage } = useAdminAuth()

const meLabel = ref('')
const canReload = ref(true)

onMounted(async () => {
  hydrateSettings()
  hydrateFromStorage()
  try {
    const cfg = await api.authConfig(apiBase.value)
    if (cfg.enabled) {
      const me = await api.me(apiBase.value)
      meLabel.value = `${me.subject} (${me.roles.join(',') || 'no-role'})`
      canReload.value = me.permissions.includes('config:reload')
    }
  }
  catch (err: any) {
    // 401/403 already routed by useAdminApi; keep shell usable for other errors.
    const auth = api.asAdminApiAuthError(err, '/admin/me')
    if (auth?.kind === 'unauthorized') {
      meLabel.value = 'session expired'
      canReload.value = false
    }
    else if (auth?.kind === 'forbidden') {
      meLabel.value = 'limited access'
      canReload.value = false
    }
  }
})

const links = computed(() => {
  const base = [
    { to: '/', label: 'Overview' },
    { to: '/topology', label: 'Topology' },
    { to: '/sessions', label: 'Sessions' },
    { to: '/audit', label: 'Audit' },
    { to: '/tickets', label: 'Tickets' },
    { to: '/vault', label: 'Vault' },
    { to: '/portal', label: 'SQL Portal' },
    { to: '/cedar', label: 'Cedar' },
  ]
  if (canReload.value) {
    base.push({ to: '/settings', label: 'Settings' })
  }
  return base
})

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
          <span v-if="meLabel"> · {{ meLabel }}</span>
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
