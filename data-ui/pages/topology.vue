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

/** UI30: client-side filters over topology snapshot. */
const q = ref('')
const protocolFilter = ref('')
const section = ref<'all' | 'listeners' | 'services' | 'endpoints' | 'pools'>('all')

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

function matches(parts: Array<string | number | undefined | null>) {
  const needle = q.value.trim().toLowerCase()
  if (!needle)
    return true
  return parts.some(p => String(p ?? '').toLowerCase().includes(needle))
}

function protoOk(proto?: string | null) {
  const f = protocolFilter.value.trim().toLowerCase()
  if (!f)
    return true
  return (proto || '').toLowerCase().includes(f)
}

const filteredListeners = computed(() =>
  listeners.value.filter(r =>
    protoOk(r.protocol)
    && matches([r.name, r.listen_addr, r.protocol, r.service, r.auth_policy]),
  ),
)

const filteredServices = computed(() =>
  services.value.filter(r =>
    protoOk(r.backend_protocol)
    && matches([
      r.name,
      r.backend_protocol,
      (r.endpoints || []).join(','),
      r.route_policy,
      r.translation_policy,
    ]),
  ),
)

const filteredEndpoints = computed(() =>
  endpoints.value.filter(r =>
    protoOk(r.protocol)
    && matches([r.name, r.protocol, r.address, r.database, r.role, r.weight]),
  ),
)

const filteredPools = computed(() =>
  pools.value.filter((r, idx) =>
    matches([
      r.name || `pool-${idx}`,
      r.capacity,
      (r.endpoints || []).map(e => e.endpoint).join(','),
    ]),
  ),
)

const protocolCounts = computed(() => {
  const c: Record<string, number> = {}
  const bump = (p?: string | null) => {
    const k = (p || '?').toLowerCase()
    c[k] = (c[k] || 0) + 1
  }
  for (const r of listeners.value)
    bump(r.protocol)
  for (const r of services.value)
    bump(r.backend_protocol)
  for (const r of endpoints.value)
    bump(r.protocol)
  return Object.entries(c).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
})

const hasFilters = computed(() => !!(q.value || protocolFilter.value || section.value !== 'all'))

function clearFilters() {
  q.value = ''
  protocolFilter.value = ''
  section.value = 'all'
}

function setProtocol(p: string) {
  protocolFilter.value = protocolFilter.value.toLowerCase() === p.toLowerCase() ? '' : p
}

function setSection(s: typeof section.value) {
  section.value = section.value === s ? 'all' : s
}

const showListeners = computed(() => section.value === 'all' || section.value === 'listeners')
const showServices = computed(() => section.value === 'all' || section.value === 'services')
const showEndpoints = computed(() => section.value === 'all' || section.value === 'endpoints')
const showPools = computed(() => section.value === 'all' || section.value === 'pools')

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
    setStatus(
      `listeners=${ls.length} services=${svcs.length} endpoints=${eps.length} pools=${pls.length} · ${new Date().toLocaleTimeString()}`,
      'ok',
    )
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
  if (timer)
    clearInterval(timer)
})
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <div>
        <h2 class="page-title">
          Topology
        </h2>
        <div
          class="status-line"
          :class="statusKind"
        >
          {{ status }}
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

    <div class="row list-filters">
      <input
        v-model="q"
        class="input"
        placeholder="Filter name / addr / service…"
        aria-label="Filter topology"
      >
      <input
        v-model="protocolFilter"
        class="input"
        placeholder="Filter protocol…"
        aria-label="Filter protocol"
      >
      <button
        type="button"
        class="btn"
        :disabled="!hasFilters"
        @click="clearFilters"
      >
        Clear
      </button>
      <span class="hint-inline">UI30 client-side · auto-refresh 15s</span>
    </div>

    <div class="row status-chips">
      <button
        type="button"
        class="chip"
        :class="{ on: section === 'all' }"
        @click="section = 'all'"
      >
        all
      </button>
      <button
        type="button"
        class="chip"
        :class="{ on: section === 'listeners' }"
        @click="setSection('listeners')"
      >
        listeners {{ listeners.length }}
      </button>
      <button
        type="button"
        class="chip"
        :class="{ on: section === 'services' }"
        @click="setSection('services')"
      >
        services {{ services.length }}
      </button>
      <button
        type="button"
        class="chip"
        :class="{ on: section === 'endpoints' }"
        @click="setSection('endpoints')"
      >
        endpoints {{ endpoints.length }}
      </button>
      <button
        type="button"
        class="chip"
        :class="{ on: section === 'pools' }"
        @click="setSection('pools')"
      >
        pools {{ pools.length }}
      </button>
      <span
        v-if="protocolCounts.length"
        class="chip-sep"
      />
      <button
        v-for="[name, n] in protocolCounts"
        :key="`p-${name}`"
        type="button"
        class="chip"
        :class="{ on: protocolFilter.toLowerCase() === name }"
        @click="setProtocol(name)"
      >
        {{ name }} {{ n }}
      </button>
    </div>

    <section
      v-if="showListeners"
      class="card"
    >
      <h2>Listeners ({{ filteredListeners.length }}/{{ listeners.length }})</h2>
      <p
        v-if="!filteredListeners.length"
        class="empty"
      >
        {{ listeners.length ? 'No listeners match filters.' : 'empty' }}
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
            v-for="row in filteredListeners"
            :key="row.name"
          >
            <td class="mono">
              <button
                type="button"
                class="linkish"
                @click="q = row.name"
              >
                {{ row.name }}
              </button>
            </td>
            <td class="mono">
              {{ row.listen_addr }}
            </td>
            <td>
              <button
                type="button"
                class="pill linkish-pill"
                @click="setProtocol(row.protocol)"
              >
                {{ row.protocol }}
              </button>
            </td>
            <td>
              <button
                type="button"
                class="linkish"
                @click="q = row.service"
              >
                {{ row.service }}
              </button>
            </td>
            <td>{{ row.auth_policy || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section
      v-if="showServices"
      class="card"
    >
      <h2>Services ({{ filteredServices.length }}/{{ services.length }})</h2>
      <p
        v-if="!filteredServices.length"
        class="empty"
      >
        {{ services.length ? 'No services match filters.' : 'empty' }}
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
            v-for="row in filteredServices"
            :key="row.name"
          >
            <td class="mono">
              <button
                type="button"
                class="linkish"
                @click="q = row.name"
              >
                {{ row.name }}
              </button>
            </td>
            <td>
              <button
                type="button"
                class="pill linkish-pill"
                @click="setProtocol(row.backend_protocol)"
              >
                {{ row.backend_protocol }}
              </button>
            </td>
            <td>{{ (row.endpoints || []).join(', ') }}</td>
            <td>{{ row.route_policy || '—' }}</td>
            <td>{{ row.translation_policy || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section
      v-if="showEndpoints"
      class="card"
    >
      <h2>Endpoints ({{ filteredEndpoints.length }}/{{ endpoints.length }})</h2>
      <p
        v-if="!filteredEndpoints.length"
        class="empty"
      >
        {{ endpoints.length ? 'No endpoints match filters.' : 'empty' }}
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
            v-for="row in filteredEndpoints"
            :key="row.name"
          >
            <td class="mono">
              <button
                type="button"
                class="linkish"
                @click="q = row.name"
              >
                {{ row.name }}
              </button>
            </td>
            <td>
              <button
                type="button"
                class="pill linkish-pill"
                @click="setProtocol(row.protocol)"
              >
                {{ row.protocol }}
              </button>
            </td>
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

    <section
      v-if="showPools"
      class="card"
    >
      <h2>Pools ({{ filteredPools.length }}/{{ pools.length }})</h2>
      <p
        v-if="!filteredPools.length"
        class="empty"
      >
        {{ pools.length ? 'No pools match filters.' : 'empty' }}
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
            v-for="(row, idx) in filteredPools"
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

<style scoped>
.page-toolbar { display: flex; justify-content: space-between; align-items: flex-start; gap: .75rem; margin-bottom: .5rem; }
.status-line { font-size: .88rem; color: #57606a; margin-top: .2rem; }
.status-line.ok { color: #1a7f37; }
.status-line.error { color: #cf222e; }
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.list-filters { margin-bottom: .55rem; }
.input {
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: .35rem .5rem;
  font: inherit;
  min-width: 12rem;
}
.hint-inline { color: #6b7280; font-size: .8rem; }
.status-chips { margin: 0 0 .65rem; gap: .4rem; }
.chip {
  border: 1px solid #d0d7de;
  background: #f6f8fa;
  border-radius: 999px;
  padding: .2rem .55rem;
  font-size: .8rem;
  cursor: pointer;
  font: inherit;
  color: #444;
}
.chip.on { border-color: #0969da; background: #ddf4ff; color: #0969da; font-weight: 600; }
.chip-sep { width: 1px; height: 1.1rem; background: #d0d7de; margin: 0 .15rem; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; margin-bottom: .75rem; }
.card h2 { margin: 0 0 .5rem; font-size: 1rem; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { border-bottom: 1px solid #eef1f4; padding: .45rem .4rem; text-align: left; vertical-align: top; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
.pill {
  display: inline-block;
  padding: .1rem .4rem;
  border-radius: 999px;
  font-size: .75rem;
  background: #ddf4ff;
  color: #0969da;
}
button.linkish, button.linkish-pill {
  background: none;
  border: none;
  padding: 0;
  color: #0969da;
  cursor: pointer;
  font: inherit;
  text-align: left;
}
button.linkish-pill {
  padding: .1rem .4rem;
  border-radius: 999px;
  background: #ddf4ff;
}
button.linkish:hover, button.linkish-pill:hover { text-decoration: underline; }
.empty { color: #888; text-align: center; padding: 1rem; margin: 0; }
</style>
