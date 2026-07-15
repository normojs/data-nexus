<script setup lang="ts">
import type {
  AdminEndpoint,
  AdminListener,
  AdminPool,
  AdminService,
  AdminSession,
} from '~/composables/useAdminApi'

useHead({ title: 'Data Nexus Admin' })

const api = useAdminApi()
const config = useRuntimeConfig()

const apiBase = ref(String(config.public.adminApiBase || 'http://127.0.0.1:8082'))
const version = ref('—')
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const reloading = ref(false)
const reloadOut = ref('—')

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

async function doReload() {
  reloading.value = true
  setStatus('Reloading config…')
  try {
    const body = await api.reload(apiBase.value)
    reloadOut.value = typeof body === 'string' ? body : JSON.stringify(body, null, 2)
    setStatus('Reload OK', 'ok')
    await loadAll()
  }
  catch (err: any) {
    reloadOut.value = err?.data ? JSON.stringify(err.data, null, 2) : String(err?.message || err)
    setStatus(err?.message || String(err), 'error')
  }
  finally {
    reloading.value = false
  }
}

let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  loadAll()
  timer = setInterval(loadAll, 15000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="admin-shell">
    <header class="admin-header">
      <div>
        <h1>Data Nexus Admin</h1>
        <div class="meta">
          {{ version }} · API
          <span class="mono">{{ apiBase }}</span>
        </div>
      </div>
      <div class="admin-actions">
        <div class="field">
          <input
            v-model="apiBase"
            placeholder="http://127.0.0.1:8082"
            @keyup.enter="loadAll"
          >
        </div>
        <button
          type="button"
          class="btn"
          @click="loadAll"
        >
          Refresh
        </button>
        <button
          type="button"
          class="btn primary"
          :disabled="reloading"
          @click="doReload"
        >
          Reload config
        </button>
        <a
          class="btn"
          :href="`${apiBase.replace(/\/$/, '')}/metrics`"
          target="_blank"
          rel="noreferrer"
        >/metrics</a>
        <a
          class="btn"
          :href="`${apiBase.replace(/\/$/, '')}/admin`"
          target="_blank"
          rel="noreferrer"
        >embedded /admin</a>
      </div>
    </header>

    <main class="admin-main">
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

      <section class="card">
        <h2>Sessions</h2>
        <p
          v-if="!sessions.length"
          class="empty"
        >
          empty
        </p>
        <table v-else>
          <thead>
            <tr>
              <th>id</th>
              <th>listener</th>
              <th>frontend</th>
              <th>peer</th>
              <th>database</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in sessions"
              :key="row.id"
            >
              <td class="mono">
                {{ row.id }}
              </td>
              <td>{{ row.listener }}</td>
              <td><span class="pill">{{ row.frontend_protocol }}</span></td>
              <td class="mono">
                {{ row.peer_addr || '—' }}
              </td>
              <td>{{ row.database || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section class="card">
        <h2>Reload result</h2>
        <pre>{{ reloadOut }}</pre>
      </section>
    </main>
  </div>
</template>
