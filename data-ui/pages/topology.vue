<script setup lang="ts">
import type {
  AdminEndpoint,
  AdminListener,
  AdminPool,
  AdminService,
} from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Topology · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()

const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const listeners = ref<AdminListener[]>([])
const services = ref<AdminService[]>([])
const endpoints = ref<AdminEndpoint[]>([])
const pools = ref<AdminPool[]>([])

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

async function loadAll() {
  setStatus('Loading…')
  const base = apiBase.value
  try {
    const [ls, svcs, eps, pls] = await Promise.all([
      api.listeners(base),
      api.services(base),
      api.endpoints(base),
      api.pools(base).catch(() => [] as AdminPool[]),
    ])
    listeners.value = ls
    services.value = svcs
    endpoints.value = eps
    pools.value = pls
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
      <h2 class="page-title">
        Topology
      </h2>
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

    <section class="card">
      <h2>Listeners</h2>
      <p
        v-if="!listeners.length"
        class="empty"
      >
        empty
      </p>
      <table v-else>
        <thead>
          <tr>
            <th>name</th>
            <th>listen_addr</th>
            <th>protocol</th>
            <th>service</th>
            <th>auth_policy</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in listeners"
            :key="row.name"
          >
            <td class="mono">
              {{ row.name }}
            </td>
            <td class="mono">
              {{ row.listen_addr }}
            </td>
            <td><span class="pill">{{ row.protocol }}</span></td>
            <td>{{ row.service }}</td>
            <td>{{ row.auth_policy || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Services</h2>
      <p
        v-if="!services.length"
        class="empty"
      >
        empty
      </p>
      <table v-else>
        <thead>
          <tr>
            <th>name</th>
            <th>backend</th>
            <th>endpoints</th>
            <th>route_policy</th>
            <th>translation_policy</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in services"
            :key="row.name"
          >
            <td class="mono">
              {{ row.name }}
            </td>
            <td><span class="pill">{{ row.backend_protocol }}</span></td>
            <td>{{ (row.endpoints || []).join(', ') }}</td>
            <td>{{ row.route_policy || '—' }}</td>
            <td>{{ row.translation_policy || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Endpoints</h2>
      <p
        v-if="!endpoints.length"
        class="empty"
      >
        empty
      </p>
      <table v-else>
        <thead>
          <tr>
            <th>name</th>
            <th>protocol</th>
            <th>address</th>
            <th>database</th>
            <th>role</th>
            <th>weight</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in endpoints"
            :key="row.name"
          >
            <td class="mono">
              {{ row.name }}
            </td>
            <td><span class="pill">{{ row.protocol }}</span></td>
            <td class="mono">
              {{ row.address }}
            </td>
            <td>{{ row.database || '—' }}</td>
            <td>{{ row.role || '—' }}</td>
            <td>{{ row.weight ?? '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Pools</h2>
      <p
        v-if="!pools.length"
        class="empty"
      >
        empty
      </p>
      <table v-else>
        <thead>
          <tr>
            <th>name</th>
            <th>capacity</th>
            <th>endpoints</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(row, idx) in pools"
            :key="row.name || idx"
          >
            <td class="mono">
              {{ row.name || `pool-${idx}` }}
            </td>
            <td>{{ row.capacity }}</td>
            <td class="mono">
              {{ (row.endpoints || []).map(e => e.endpoint).join(', ') || '—' }}
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
