<script setup lang="ts">
import type { AdminSession } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Sessions · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()

const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const sessions = ref<AdminSession[]>([])

/** UI25: client-side filters over the loaded session snapshot. */
const listenerFilter = ref('')
const protocolFilter = ref('')
const databaseFilter = ref('')
const peerFilter = ref('')

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

const filteredSessions = computed(() => {
  const lis = listenerFilter.value.trim().toLowerCase()
  const proto = protocolFilter.value.trim().toLowerCase()
  const db = databaseFilter.value.trim().toLowerCase()
  const peer = peerFilter.value.trim().toLowerCase()
  return sessions.value.filter((s) => {
    if (lis && !(s.listener || '').toLowerCase().includes(lis))
      return false
    if (proto && !(s.frontend_protocol || '').toLowerCase().includes(proto))
      return false
    if (db && !(s.database || '').toLowerCase().includes(db))
      return false
    if (peer && !(s.peer_addr || '').toLowerCase().includes(peer))
      return false
    return true
  })
})

const listenerCounts = computed(() => {
  const c: Record<string, number> = {}
  for (const s of sessions.value) {
    const k = s.listener || '(none)'
    c[k] = (c[k] || 0) + 1
  }
  return Object.entries(c).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
})

const protocolCounts = computed(() => {
  const c: Record<string, number> = {}
  for (const s of sessions.value) {
    const k = (s.frontend_protocol || '(none)').toLowerCase()
    c[k] = (c[k] || 0) + 1
  }
  return Object.entries(c).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
})

const hasFilters = computed(() =>
  !!(listenerFilter.value || protocolFilter.value || databaseFilter.value || peerFilter.value),
)

function clearListFilters() {
  listenerFilter.value = ''
  protocolFilter.value = ''
  databaseFilter.value = ''
  peerFilter.value = ''
}

function setListenerFilter(name: string) {
  const v = name === '(none)' ? '' : name
  listenerFilter.value = listenerFilter.value === v ? '' : v
}

function setProtocolFilter(name: string) {
  const v = name === '(none)' ? '' : name
  protocolFilter.value = protocolFilter.value.toLowerCase() === v.toLowerCase() ? '' : v
}

async function loadAll() {
  setStatus('Loading…')
  try {
    sessions.value = await api.sessions(apiBase.value)
    const bits = protocolCounts.value.map(([p, n]) => `${p}=${n}`).join(' ')
    const bit = bits ? ` · ${bits}` : ''
    setStatus(
      `${sessions.value.length} sessions${bit} · ${new Date().toLocaleTimeString()}`,
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
  timer = setInterval(loadAll, 10000)
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
          Sessions
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

    <section class="card">
      <h2>Active sessions ({{ sessions.length }})</h2>
      <div class="row list-filters">
        <label>
          <span class="sr">Listener</span>
          <input
            v-model="listenerFilter"
            class="input"
            placeholder="Filter listener…"
            aria-label="Filter by listener"
          >
        </label>
        <label>
          <span class="sr">Protocol</span>
          <input
            v-model="protocolFilter"
            class="input"
            placeholder="Filter protocol…"
            aria-label="Filter by frontend protocol"
          >
        </label>
        <label>
          <span class="sr">Database</span>
          <input
            v-model="databaseFilter"
            class="input"
            placeholder="Filter database…"
            aria-label="Filter by database"
          >
        </label>
        <label>
          <span class="sr">Peer</span>
          <input
            v-model="peerFilter"
            class="input"
            placeholder="Filter peer…"
            aria-label="Filter by peer address"
          >
        </label>
        <button
          type="button"
          class="btn"
          :disabled="!hasFilters"
          @click="clearListFilters"
        >
          Clear filters
        </button>
        <span class="hint-inline">
          showing {{ filteredSessions.length }} / {{ sessions.length }}
          <template v-if="hasFilters">
            (client-side)
          </template>
        </span>
      </div>
      <p class="hint">
        UI25: listener / protocol / database / peer filters are client-side over the
        auto-refresh snapshot (10s). Click chips or table cells to toggle filters.
        Process-local SQL cursors (<code class="mono">DECLARE … [WITH HOLD]</code>) and
        PortalSuspended holds live only while this session is connected — disconnect
        clears them (not a backend server-side <code class="mono">WITH HOLD</code> cursor).
      </p>
      <div
        v-if="listenerCounts.length"
        class="row status-chips"
      >
        <button
          v-for="[name, n] in listenerCounts"
          :key="`lis-${name}`"
          type="button"
          class="chip"
          :class="{ on: listenerFilter === (name === '(none)' ? '' : name) || (name !== '(none)' && listenerFilter === name) }"
          @click="setListenerFilter(name)"
        >
          {{ name }} {{ n }}
        </button>
      </div>
      <div
        v-if="protocolCounts.length"
        class="row status-chips"
      >
        <button
          v-for="[name, n] in protocolCounts"
          :key="`proto-${name}`"
          type="button"
          class="chip"
          :class="{ on: protocolFilter.toLowerCase() === name.toLowerCase() }"
          @click="setProtocolFilter(name)"
        >
          {{ name }} {{ n }}
        </button>
      </div>

      <p
        v-if="!sessions.length"
        class="empty"
      >
        No active sessions.
      </p>
      <p
        v-else-if="!filteredSessions.length"
        class="empty"
      >
        No sessions match filters.
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
            v-for="row in filteredSessions"
            :key="row.id"
          >
            <td class="mono">
              {{ row.id }}
            </td>
            <td>
              <button
                type="button"
                class="linkish"
                :title="`Filter listener=${row.listener}`"
                @click="setListenerFilter(row.listener || '(none)')"
              >
                {{ row.listener || '—' }}
              </button>
            </td>
            <td>
              <button
                type="button"
                class="pill linkish-pill"
                :title="`Filter protocol=${row.frontend_protocol}`"
                @click="setProtocolFilter(row.frontend_protocol || '(none)')"
              >
                {{ row.frontend_protocol }}
              </button>
            </td>
            <td class="mono">
              <button
                type="button"
                class="linkish"
                :title="row.peer_addr ? `Filter peer=${row.peer_addr}` : ''"
                :disabled="!row.peer_addr"
                @click="peerFilter = peerFilter === (row.peer_addr || '') ? '' : (row.peer_addr || '')"
              >
                {{ row.peer_addr || '—' }}
              </button>
            </td>
            <td>
              <button
                type="button"
                class="linkish"
                :title="row.database ? `Filter database=${row.database}` : ''"
                :disabled="!row.database"
                @click="databaseFilter = databaseFilter === (row.database || '') ? '' : (row.database || '')"
              >
                {{ row.database || '—' }}
              </button>
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
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; }
.card h2 { margin: 0 0 .5rem; font-size: 1rem; }
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.list-filters { margin-bottom: .5rem; gap: .55rem; }
.list-filters label { display: flex; flex-direction: column; gap: .15rem; min-width: 8rem; }
.list-filters .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
.input {
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: .35rem .5rem;
  font: inherit;
}
.hint { color: #57606a; font-size: .88rem; margin: 0 0 .65rem; }
.hint-inline { color: #6b7280; font-size: .8rem; }
.status-chips { margin: 0 0 .55rem; gap: .4rem; }
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
  border: 0;
  font: inherit;
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
button.linkish:disabled {
  color: #888;
  cursor: default;
}
button.linkish-pill {
  padding: .1rem .4rem;
  border-radius: 999px;
  background: #ddf4ff;
}
button.linkish-pill:hover, button.linkish:not(:disabled):hover {
  text-decoration: underline;
}
.empty { color: #888; text-align: center; padding: 1rem; margin: 0; }
</style>
