<script setup lang="ts">
import type { AdminAuditEvent } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Audit · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()
const events = ref<AdminAuditEvent[]>([])
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const source = ref('')
const decision = ref('')
const service = ref('')
const subjectId = ref('')
const eventId = ref('')
const fromLocal = ref('')
const toLocal = ref('')

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

function localToMs(v: string): number | undefined {
  if (!v) return undefined
  const t = Date.parse(v)
  return Number.isFinite(t) ? t : undefined
}

function fmtMs(ms?: number) {
  if (ms == null) return '—'
  try {
    return new Date(ms).toLocaleString()
  }
  catch {
    return String(ms)
  }
}

async function load() {
  setStatus('Loading…')
  try {
    const res = await api.auditEvents({
      decision: decision.value || undefined,
      service: service.value || undefined,
      subject_id: subjectId.value || undefined,
      event_id: eventId.value || undefined,
      from_ms: localToMs(fromLocal.value),
      to_ms: localToMs(toLocal.value),
      limit: 100,
    }, apiBase.value)
    events.value = res.events || []
    source.value = res.source || '—'
    const note = res.note ? ` · ${res.note}` : ''
    setStatus(`${events.value.length} events · source=${source.value}${note}`, 'ok')
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
}

function clearFilters() {
  decision.value = ''
  service.value = ''
  subjectId.value = ''
  eventId.value = ''
  fromLocal.value = ''
  toLocal.value = ''
  load()
}

onMounted(() => {
  hydrate()
  load()
})
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <div>
        <h2 class="page-title">
          Audit
        </h2>
        <div
          class="meta"
          :class="{ ok: statusKind === 'ok', err: statusKind === 'error' }"
        >
          {{ status }}
        </div>
      </div>
      <div class="row">
        <button
          type="button"
          class="btn"
          @click="load"
        >
          Refresh
        </button>
        <button
          type="button"
          class="btn"
          @click="clearFilters"
        >
          Clear
        </button>
      </div>
    </div>

    <div class="card filters">
      <div class="form-grid">
        <label>
          <span>Decision</span>
          <input
            v-model="decision"
            class="input"
            placeholder="deny / execute / allow"
          >
        </label>
        <label>
          <span>Service</span>
          <input
            v-model="service"
            class="input"
            placeholder="orders"
          >
        </label>
        <label>
          <span>Subject</span>
          <input
            v-model="subjectId"
            class="input"
            placeholder="subject_id"
          >
        </label>
        <label>
          <span>Event id</span>
          <input
            v-model="eventId"
            class="input mono"
            placeholder="ae-…"
          >
        </label>
        <label>
          <span>From</span>
          <input
            v-model="fromLocal"
            class="input"
            type="datetime-local"
          >
        </label>
        <label>
          <span>To</span>
          <input
            v-model="toLocal"
            class="input"
            type="datetime-local"
          >
        </label>
      </div>
      <p class="hint">
        B06: when <code class="mono">security.audit.index_path</code> is set, API returns
        <code class="mono">source=index</code> (SQLite side-index); otherwise
        <code class="mono">source=recent</code> (in-memory ring).
      </p>
    </div>

    <div class="card">
      <table class="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Decision</th>
            <th>Subject</th>
            <th>Service</th>
            <th>Outcome</th>
            <th>Event id</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(e, i) in events"
            :key="e.event_id || i"
          >
            <td class="mono">
              {{ fmtMs(e.ts_unix_ms) }}
            </td>
            <td class="mono">
              {{ e.decision }}
            </td>
            <td>{{ e.subject_id }}</td>
            <td>{{ e.service }}</td>
            <td class="mono">
              {{ e.outcome }}
            </td>
            <td class="mono eid">
              {{ e.event_id }}
            </td>
            <td class="msg">
              {{ e.message || e.rule }}
            </td>
          </tr>
          <tr v-if="!events.length">
            <td
              colspan="7"
              class="empty"
            >
              No events.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.filters { margin-bottom: .75rem; }
.form-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: .65rem .75rem;
  margin-bottom: .5rem;
}
.form-grid label { display: flex; flex-direction: column; gap: .25rem; font-size: .85rem; color: #444; }
.input { border: 1px solid #d0d7de; border-radius: 6px; padding: .35rem .5rem; min-width: 0; font: inherit; }
.hint { color: #57606a; font-size: .85rem; margin: 0; }
.table { width: 100%; border-collapse: collapse; font-size: .9rem; }
.table th, .table td { border-bottom: 1px solid #eef1f4; padding: .45rem .4rem; text-align: left; vertical-align: top; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
.eid { max-width: 12rem; word-break: break-all; }
.msg { max-width: 22rem; word-break: break-word; color: #444; }
.meta.ok { color: #1a7f37; }
.meta.err { color: #cf222e; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; }
.empty { color: #888; text-align: center; padding: 1rem; }
@media (max-width: 900px) {
  .form-grid { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 560px) {
  .form-grid { grid-template-columns: 1fr; }
}
</style>
