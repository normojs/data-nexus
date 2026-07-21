<script setup lang="ts">
import type { AdminAuditEvent, AdminAuditStats } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Audit · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()
const events = ref<AdminAuditEvent[]>([])
const stats = ref<AdminAuditStats | null>(null)
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const source = ref('')
const note = ref('')
const decision = ref('')
const service = ref('')
const subjectId = ref('')
const eventId = ref('')
const fromLocal = ref('')
const toLocal = ref('')
const limit = ref(100)
const selectedEvent = ref<AdminAuditEvent | null>(null)

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

function fmtNum(n?: number) {
  if (n == null || Number.isNaN(n)) return '—'
  return String(n)
}

/** B08: compact sample presence for the event table. */
function sampleLabel(e: AdminAuditEvent): string {
  if (e.sample_row_count != null) {
    return `${e.sample_row_count}r${e.sample_truncated ? '…' : ''}`
  }
  if (e.sample_ref) return 'ref'
  if (e.sample_body) return 'body'
  return '—'
}

function selectEvent(e: AdminAuditEvent) {
  if (selectedEvent.value?.event_id && selectedEvent.value.event_id === e.event_id) {
    selectedEvent.value = null
    return
  }
  selectedEvent.value = e
}

function sampleTitle(e: AdminAuditEvent): string {
  const parts: string[] = []
  if (e.sample_row_count != null) parts.push(`rows=${e.sample_row_count}`)
  if (e.sample_bytes != null) parts.push(`bytes=${e.sample_bytes}`)
  if (e.sample_truncated) parts.push('truncated')
  if (e.sample_ref) parts.push(`ref=${e.sample_ref}`)
  if (e.sample_body) {
    const preview =
      e.sample_body.length > 240 ? `${e.sample_body.slice(0, 240)}…` : e.sample_body
    parts.push(preview)
  }
  return parts.join(' · ') || 'no sample (need sample_enabled + default_audit_level=L2)'
}

const sourceBadgeClass = computed(() => {
  if (source.value === 'index') return 'src-index'
  if (source.value === 'recent') return 'src-recent'
  return 'src-unknown'
})

const statCards = computed(() => {
  const s = stats.value
  if (!s) {
    return [
      { label: 'Accepted', value: '—' },
      { label: 'Written', value: '—' },
      { label: 'Dropped', value: '—' },
      { label: 'Priority accepted', value: '—' },
      { label: 'Queue depth', value: '—' },
      { label: 'Index rows', value: '—' },
    ]
  }
  return [
    { label: 'Accepted', value: fmtNum(s.accepted) },
    { label: 'Written', value: fmtNum(s.written) },
    {
      label: 'Dropped',
      value: fmtNum(s.dropped),
      warn: (s.dropped || 0) > 0,
    },
    {
      label: 'Priority accepted',
      value: fmtNum(s.priority_accepted),
      hint: `cap ${fmtNum(s.priority_queue_capacity)} · drop ${fmtNum(s.priority_dropped)}`,
    },
    {
      label: 'Queue depth',
      value: `${fmtNum(s.queue_len)} / ${fmtNum(s.queue_capacity)}`,
      hint: `priority ${fmtNum(s.priority_queue_len)}`,
    },
    {
      label: 'Index',
      value: s.index_enabled ? fmtNum(s.index_rows) : 'off',
      hint: s.index_enabled
        ? `ins ${fmtNum(s.index_inserted)} · err ${fmtNum(s.index_errors)}`
        : 'source=recent ring',
    },
  ]
})

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
      limit: Math.min(1000, Math.max(1, Number(limit.value) || 100)),
    }, apiBase.value)
    events.value = res.events || []
    source.value = res.source || '—'
    note.value = res.note || ''
    if (res.stats) {
      stats.value = res.stats
    }
    else {
      // Fallback dedicated stats endpoint when events omitted stats.
      try {
        stats.value = await api.auditStats(apiBase.value)
      }
      catch {
        stats.value = null
      }
    }
    const notePart = note.value ? ` · ${note.value}` : ''
    setStatus(`${events.value.length} events${notePart}`, 'ok')
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
  limit.value = 100
  load()
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function exportJson() {
  if (!events.value.length) {
    setStatus('Nothing to export', 'error')
    return
  }
  const payload = {
    exported_at: new Date().toISOString(),
    source: source.value,
    filters: {
      decision: decision.value || null,
      service: service.value || null,
      subject_id: subjectId.value || null,
      event_id: eventId.value || null,
      from: fromLocal.value || null,
      to: toLocal.value || null,
      limit: limit.value,
    },
    events: events.value,
  }
  downloadBlob(
    `data-nexus-audit-${Date.now()}.json`,
    new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
  )
  setStatus(`Exported ${events.value.length} events as JSON`, 'ok')
}

function csvEscape(v: unknown) {
  const s = v == null ? '' : String(v)
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

function exportCsv() {
  if (!events.value.length) {
    setStatus('Nothing to export', 'error')
    return
  }
  const headers = [
    'ts_unix_ms',
    'time_local',
    'decision',
    'subject_id',
    'service',
    'outcome',
    'rule',
    'event_id',
    'listener',
    'command_type',
    'sql_fingerprint',
    'message',
    'audit_level',
    'sample_row_count',
    'sample_bytes',
    'sample_truncated',
    'sample_ref',
    'sample_body',
  ]
  const lines = [headers.join(',')]
  for (const e of events.value) {
    lines.push([
      e.ts_unix_ms ?? '',
      fmtMs(e.ts_unix_ms),
      e.decision ?? '',
      e.subject_id ?? '',
      e.service ?? '',
      e.outcome ?? '',
      e.rule ?? '',
      e.event_id ?? '',
      e.listener ?? '',
      e.command_type ?? '',
      e.sql_fingerprint ?? '',
      e.message ?? '',
      e.audit_level ?? '',
      e.sample_row_count ?? '',
      e.sample_bytes ?? '',
      e.sample_truncated ? 'true' : '',
      e.sample_ref ?? '',
      // Keep sample_body last; may be large but still bounded server-side.
      e.sample_body ?? '',
    ].map(csvEscape).join(','))
  }
  downloadBlob(
    `data-nexus-audit-${Date.now()}.csv`,
    new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' }),
  )
  setStatus(`Exported ${events.value.length} events as CSV (includes sample_* when present)`, 'ok')
}

function copyEventId(id?: string) {
  if (!id || !import.meta.client) return
  navigator.clipboard?.writeText(id).then(() => {
    setStatus(`Copied ${id}`, 'ok')
  }).catch(() => {
    eventId.value = id
    setStatus('Filled event id filter', 'ok')
  })
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
          <span
            v-if="source"
            class="src-badge"
            :class="sourceBadgeClass"
            :title="note || `Query source: ${source}`"
          >source={{ source }}</span>
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
        <button
          type="button"
          class="btn"
          :disabled="!events.length"
          @click="exportJson"
        >
          Export JSON
        </button>
        <button
          type="button"
          class="btn"
          :disabled="!events.length"
          @click="exportCsv"
        >
          Export CSV
        </button>
      </div>
    </div>

    <div class="stats-grid">
      <div
        v-for="c in statCards"
        :key="c.label"
        class="stat-card"
        :class="{ warn: c.warn }"
      >
        <div class="stat-label">
          {{ c.label }}
        </div>
        <div class="stat-value mono">
          {{ c.value }}
        </div>
        <div
          v-if="c.hint"
          class="stat-hint"
        >
          {{ c.hint }}
        </div>
      </div>
    </div>

    <div class="card filters">
      <div class="form-grid">
        <label>
          <span>Decision</span>
          <input
            v-model="decision"
            class="input"
            list="decision-opts"
            placeholder="deny / allow / execute"
            @keyup.enter="load"
          >
          <datalist id="decision-opts">
            <option value="deny" />
            <option value="allow" />
            <option value="allow_obligations" />
            <option value="require_ticket" />
            <option value="execute" />
          </datalist>
        </label>
        <label>
          <span>Service</span>
          <input
            v-model="service"
            class="input"
            placeholder="orders"
            @keyup.enter="load"
          >
        </label>
        <label>
          <span>Subject</span>
          <input
            v-model="subjectId"
            class="input"
            placeholder="subject_id"
            @keyup.enter="load"
          >
        </label>
        <label>
          <span>Event id</span>
          <input
            v-model="eventId"
            class="input mono"
            placeholder="ae-…"
            @keyup.enter="load"
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
        <label>
          <span>Limit</span>
          <input
            v-model.number="limit"
            class="input"
            type="number"
            min="1"
            max="1000"
            @keyup.enter="load"
          >
        </label>
      </div>
      <p class="hint">
        UI03: stats from pipeline (B06 index / B07 priority queue). When
        <code class="mono">security.audit.index_path</code> is set, badge shows
        <code class="mono">source=index</code>; otherwise
        <code class="mono">source=recent</code> (in-memory ring). Export is the
        <strong>currently loaded</strong> filter result (client-side), not a
        separate server dump API.
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
            <th>Rule</th>
            <th>Sample</th>
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
            <td>
              <span
                class="dec"
                :class="{
                  deny: e.decision === 'deny',
                  allow: e.decision === 'allow' || e.decision === 'allow_obligations',
                  ticket: e.decision === 'require_ticket',
                }"
              >{{ e.decision || '—' }}</span>
            </td>
            <td>{{ e.subject_id || '—' }}</td>
            <td>{{ e.service || '—' }}</td>
            <td class="mono">
              {{ e.outcome || '—' }}
            </td>
            <td class="mono">
              {{ e.rule || '—' }}
            </td>
            <td class="mono sample">
              <button
                v-if="sampleLabel(e) !== '—'"
                type="button"
                class="linkish"
                :title="sampleTitle(e)"
                @click="selectEvent(e)"
              >
                {{ sampleLabel(e) }}
              </button>
              <span
                v-else
                title="no sample (need sample_enabled + default_audit_level=L2)"
              >—</span>
            </td>
            <td class="mono eid">
              <button
                v-if="e.event_id"
                type="button"
                class="linkish"
                :title="'Copy ' + e.event_id"
                @click="copyEventId(e.event_id)"
              >
                {{ e.event_id }}
              </button>
              <span v-else>—</span>
            </td>
            <td class="msg">
              {{ e.message || e.sql_fingerprint || '—' }}
            </td>
          </tr>
          <tr v-if="!events.length">
            <td
              colspan="9"
              class="empty"
            >
              No events.
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-if="selectedEvent && (selectedEvent.sample_body || selectedEvent.sample_ref)"
      class="card sample-detail"
    >
      <div class="row">
        <h3 class="page-title">
          Sample detail
        </h3>
        <button
          type="button"
          class="btn"
          @click="selectedEvent = null"
        >
          Close
        </button>
      </div>
      <p class="hint mono">
        event={{ selectedEvent.event_id || '—' }}
        · rows={{ selectedEvent.sample_row_count ?? '—' }}
        · bytes={{ selectedEvent.sample_bytes ?? '—' }}
        · truncated={{ selectedEvent.sample_truncated ? 'yes' : 'no' }}
        · ref={{ selectedEvent.sample_ref || '—' }}
      </p>
      <pre
        v-if="selectedEvent.sample_body"
        class="sample-pre mono"
      >{{ selectedEvent.sample_body }}</pre>
      <p
        v-else
        class="hint"
      >
        No inline sample_body (OpenDAL ref only or stripped).
      </p>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.page-title { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
.src-badge {
  font-size: .72rem;
  font-weight: 600;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  padding: .15rem .45rem;
  border-radius: 999px;
  vertical-align: middle;
}
.src-index { background: #ddf4ff; color: #0969da; }
.src-recent { background: #fff8c5; color: #9a6700; }
.src-unknown { background: #f6f8fa; color: #57606a; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: .55rem;
  margin-bottom: .75rem;
}
.stat-card {
  background: #fff;
  border: 1px solid #e6ebf0;
  border-radius: 10px;
  padding: .55rem .65rem;
}
.stat-card.warn { border-color: #ff8182; background: #fff5f5; }
.stat-label { font-size: .75rem; color: #57606a; margin-bottom: .2rem; }
.stat-value { font-size: 1.05rem; font-weight: 600; }
.stat-hint { font-size: .72rem; color: #888; margin-top: .15rem; }
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
.msg { max-width: 20rem; word-break: break-word; color: #444; }
.linkish {
  background: none;
  border: 0;
  padding: 0;
  color: #0969da;
  cursor: pointer;
  font: inherit;
  text-align: left;
  word-break: break-all;
}
.linkish:hover { text-decoration: underline; }
.dec {
  display: inline-block;
  padding: .08rem .35rem;
  border-radius: 999px;
  font-size: .75rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  background: #f6f8fa;
  color: #444;
}
.dec.deny { background: #ffebe9; color: #cf222e; }
.dec.allow { background: #dafbe1; color: #1a7f37; }
.dec.ticket { background: #fff8c5; color: #9a6700; }
.meta.ok { color: #1a7f37; }
.meta.err { color: #cf222e; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; }
.empty { color: #888; text-align: center; padding: 1rem; }
@media (max-width: 1100px) {
  .stats-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .form-grid { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 560px) {
  .form-grid { grid-template-columns: 1fr; }
  .stats-grid { grid-template-columns: 1fr 1fr; }
}
</style>
