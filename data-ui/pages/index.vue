<script setup lang="ts">
import type {
  AdminEndpoint,
  AdminListener,
  AdminPool,
  AdminService,
  AdminSession,
} from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Overview · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()

const version = ref('—')
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const listeners = ref<AdminListener[]>([])
const services = ref<AdminService[]>([])
const endpoints = ref<AdminEndpoint[]>([])
const pools = ref<AdminPool[]>([])
const sessions = ref<AdminSession[]>([])

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

async function loadAll() {
  setStatus('Loading…')
  const base = apiBase.value
  try {
    const [ver, ls, svcs, eps, pls, sess] = await Promise.all([
      api.version(base).catch(() => 'Data Nexus'),
      api.listeners(base),
      api.services(base),
      api.endpoints(base),
      api.pools(base).catch(() => [] as AdminPool[]),
      api.sessions(base),
    ])
    version.value = String(ver || 'Data Nexus').trim()
    listeners.value = ls
    services.value = svcs
    endpoints.value = eps
    pools.value = pls
    sessions.value = sess
    setStatus(`Updated ${new Date().toLocaleTimeString()}`, 'ok')
  }
  catch (err: any) {
    setStatus(err?.data?.message || err?.message || String(err), 'error')
  }
}

let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  hydrateSettings()
  loadAll()
  timer = setInterval(loadAll, 15000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <div>
        <h2 class="page-title">
          Overview
        </h2>
        <div class="meta">
          {{ version }}
        </div>
      </div>
      <button
        type="button"
        class="btn"
        @click="loadAll"
      >
        Refresh
      </button>
    </div>

    <div
      class="status-line"
      :class="statusKind"
    >
      {{ status }}
    </div>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="label">
          Listeners
        </div>
        <div class="value">
          {{ listeners.length }}
        </div>
      </div>
      <div class="stat-card">
        <div class="label">
          Services
        </div>
        <div class="value">
          {{ services.length }}
        </div>
      </div>
      <div class="stat-card">
        <div class="label">
          Endpoints
        </div>
        <div class="value">
          {{ endpoints.length }}
        </div>
      </div>
      <div class="stat-card">
        <div class="label">
          Sessions
        </div>
        <div class="value">
          {{ sessions.length }}
        </div>
      </div>
      <div class="stat-card">
        <div class="label">
          Pools
        </div>
        <div class="value">
          {{ pools.length }}
        </div>
      </div>
    </div>

    <section class="card">
      <h2>Quick links</h2>
      <div class="admin-actions">
        <NuxtLink
          class="btn"
          to="/topology"
        >
          Topology
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/sessions"
        >
          Sessions
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/settings"
        >
          Settings / Reload
        </NuxtLink>
      </div>
    </section>
  </div>
</template>
