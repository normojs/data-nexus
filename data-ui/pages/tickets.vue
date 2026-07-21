<script setup lang="ts">
import type { AdminMe, AdminSecurityPolicies, AdminTicket } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Tickets · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()

const tickets = ref<AdminTicket[]>([])
const policyState = ref<AdminSecurityPolicies['state'] | null>(null)
const adminMe = ref<AdminMe | null>(null)
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const busy = ref(false)

// Issue form
const subjectId = ref('')
const sql = ref('DROP TABLE IF EXISTS demo_t')
const ticketType = ref('ddl')
const ttlSecs = ref(600)
const maxUses = ref(1)
const dualControl = ref(true)
const note = ref('')

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

function fmtMs(ms?: number | null) {
  if (!ms) return '—'
  try {
    return new Date(ms).toLocaleString()
  }
  catch {
    return String(ms)
  }
}

function remaining(t: AdminTicket) {
  return Math.max(0, (t.max_uses || 0) - (t.uses || 0))
}

async function load() {
  setStatus('Loading tickets…')
  try {
    const [list, policies, me] = await Promise.all([
      api.tickets(100, apiBase.value),
      api.securityPolicies(apiBase.value).catch(() => null),
      api.me(apiBase.value).catch(() => null),
    ])
    tickets.value = list
    policyState.value = policies?.state ?? null
    adminMe.value = me
    const st = policyState.value
    const stateBit = st
      ? ` · state=${st.backend}${st.ticket_encrypt_configured ? '+enc' : ''}`
      : ''
    const meBit = adminMe.value?.subject ? ` · as ${adminMe.value.subject}` : ''
    setStatus(`${tickets.value.length} tickets${stateBit}${meBit}`, 'ok')
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
}

async function issue() {
  if (!subjectId.value.trim() || !sql.value.trim()) {
    setStatus('subject_id and sql are required', 'error')
    return
  }
  busy.value = true
  setStatus('Issuing ticket…')
  try {
    const t = await api.issueTicket({
      subject_id: subjectId.value.trim(),
      sql: sql.value,
      ticket_type: ticketType.value || 'high_risk',
      ttl_secs: ttlSecs.value || 600,
      max_uses: maxUses.value || 1,
      dual_control: dualControl.value,
      note: note.value || undefined,
    }, apiBase.value)
    setStatus(
      dualControl.value
        ? `Issued ${t.id} (pending dual-control approval)`
        : `Issued ${t.id} (active)`,
      'ok',
    )
    await load()
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

async function approve(id: string) {
  const ticket = tickets.value.find(x => x.id === id)
  const me = adminMe.value?.subject?.trim()
  if (
    ticket?.dual_control
    && me
    && ticket.issued_by
    && ticket.issued_by.trim().toLowerCase() === me.toLowerCase()
  ) {
    setStatus(
      `Cannot self-approve dual-control ticket ${id}: approver must differ from issuer (${ticket.issued_by})`,
      'error',
    )
    return
  }
  busy.value = true
  try {
    const t = await api.approveTicket(id, {}, apiBase.value)
    setStatus(`Approved ${t.id} as ${me || t.approved_by || 'admin'}`, 'ok')
    await load()
  }
  catch (e: any) {
    const msg = e?.data?.message || e?.message || String(e)
    setStatus(msg, 'error')
  }
  finally {
    busy.value = false
  }
}

async function reject(id: string) {
  const reason = window.prompt('Reject reason (optional)') ?? undefined
  busy.value = true
  try {
    const t = await api.rejectTicket(id, { reason }, apiBase.value)
    setStatus(`Rejected ${t.id}`, 'ok')
    await load()
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

async function revoke(id: string) {
  const reason = window.prompt('Revoke reason (optional)') ?? undefined
  busy.value = true
  try {
    const t = await api.revokeTicket(id, { reason }, apiBase.value)
    setStatus(`Revoked ${t.id}`, 'ok')
    await load()
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

async function prune() {
  busy.value = true
  try {
    const r = await api.pruneTickets(apiBase.value)
    const n = r.removed ?? r.pruned ?? 0
    setStatus(`Pruned ${n} expired tickets`, 'ok')
    await load()
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

function copyComment(id: string) {
  const text = `/*dn_ticket:${id}*/`
  if (import.meta.client && navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => setStatus(`Copied ${text}`, 'ok'))
  }
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
          Tickets
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
          :disabled="busy"
          @click="load"
        >
          Refresh
        </button>
        <button
          type="button"
          class="btn"
          :disabled="busy"
          @click="prune"
        >
          Prune expired
        </button>
      </div>
    </div>

    <div
      v-if="policyState"
      class="card state-banner mono"
    >
      H05 state: backend={{ policyState.backend }}
      · ticket_enc={{ policyState.ticket_encrypt_configured ? 'yes' : 'no' }}
      · poll_ms={{ policyState.policy_poll_ms }}
      <template v-if="policyState.backend === 'file'">
        · ticket={{ policyState.ticket_path || '—' }}
      </template>
      <span class="hint-inline"> (file backend last-writer-wins, not CRDT)</span>
    </div>

    <div class="card form-card">
      <h3>Issue ticket</h3>
      <p class="hint">
        High-risk SQL (DDL / write-no-where) embeds
        <code class="mono">/*dn_ticket:&lt;id&gt;*/</code>. Dual-control starts as
        <strong>pending</strong> until a second person approves.
      </p>
      <div class="form-grid">
        <label>
          <span>Subject id</span>
          <input
            v-model="subjectId"
            class="input"
            placeholder="data-plane subject (protocol user)"
          >
        </label>
        <label>
          <span>Ticket type</span>
          <input
            v-model="ticketType"
            class="input"
            placeholder="ddl / high_risk"
          >
        </label>
        <label>
          <span>TTL seconds</span>
          <input
            v-model.number="ttlSecs"
            class="input"
            type="number"
            min="60"
          >
        </label>
        <label>
          <span>Max uses</span>
          <input
            v-model.number="maxUses"
            class="input"
            type="number"
            min="1"
          >
        </label>
        <label class="span-2">
          <span>SQL</span>
          <textarea
            v-model="sql"
            class="input area"
            rows="3"
            placeholder="SQL to authorize"
          />
        </label>
        <label class="span-2">
          <span>Note</span>
          <input
            v-model="note"
            class="input"
            placeholder="optional"
          >
        </label>
        <label class="check">
          <input
            v-model="dualControl"
            type="checkbox"
          >
          Dual-control (second approver required; approver ≠ issuer; uses logged-in admin subject)
        </label>
      </div>
      <div class="row">
        <button
          type="button"
          class="btn primary"
          :disabled="busy"
          @click="issue"
        >
          Issue ticket
        </button>
      </div>
    </div>

    <div class="card">
      <table class="table">
        <thead>
          <tr>
            <th>Id</th>
            <th>Status</th>
            <th>Type</th>
            <th>Subject</th>
            <th>Uses</th>
            <th>Expires</th>
            <th>Issuer / Approver</th>
            <th>SQL sample</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="t in tickets"
            :key="t.id"
          >
            <td class="mono">
              <button
                type="button"
                class="linkish"
                title="Copy /*dn_ticket:…*/"
                @click="copyComment(t.id)"
              >
                {{ t.id }}
              </button>
            </td>
            <td>
              <span
                class="badge"
                :class="t.status"
              >{{ t.status }}</span>
              <span
                v-if="t.dual_control"
                class="badge dual"
              >dual</span>
            </td>
            <td class="mono">
              {{ t.ticket_type }}
            </td>
            <td>{{ t.subject_id }}</td>
            <td class="mono">
              {{ t.uses }}/{{ t.max_uses }} ({{ remaining(t) }} left)
            </td>
            <td class="mono">
              {{ fmtMs(t.expires_at_unix_ms) }}
            </td>
            <td>
              <div>{{ t.issued_by || '—' }}</div>
              <div
                v-if="t.approved_by"
                class="sub"
              >
                ✓ {{ t.approved_by }}
              </div>
              <div
                v-if="t.rejected_by"
                class="sub err"
              >
                ✗ {{ t.rejected_by }}
              </div>
            </td>
            <td class="msg mono">
              {{ t.sql_sample || t.sql_fingerprint }}
            </td>
            <td class="actions">
              <button
                v-if="t.status === 'pending'"
                type="button"
                class="btn primary"
                :disabled="busy"
                @click="approve(t.id)"
              >
                Approve
              </button>
              <button
                v-if="t.status === 'pending'"
                type="button"
                class="btn"
                :disabled="busy"
                @click="reject(t.id)"
              >
                Reject
              </button>
              <button
                v-if="t.status === 'active' || t.status === 'pending'"
                type="button"
                class="btn"
                :disabled="busy"
                @click="revoke(t.id)"
              >
                Revoke
              </button>
            </td>
          </tr>
          <tr v-if="!tickets.length">
            <td
              colspan="9"
              class="empty"
            >
              No tickets yet.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.form-card h3 { margin: 0 0 .35rem; font-size: 1rem; }
.hint { color: #57606a; font-size: .88rem; margin: 0 0 .75rem; }
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: .65rem .75rem;
  margin-bottom: .75rem;
}
.form-grid label { display: flex; flex-direction: column; gap: .25rem; font-size: .85rem; color: #444; }
.form-grid .span-2 { grid-column: 1 / -1; }
.form-grid .check { flex-direction: row; align-items: center; gap: .4rem; }
.input {
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: .35rem .5rem;
  font: inherit;
}
.area { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
.table { width: 100%; border-collapse: collapse; font-size: .88rem; }
.table th, .table td {
  border-bottom: 1px solid #eef1f4;
  padding: .45rem .4rem;
  text-align: left;
  vertical-align: top;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
.msg { max-width: 16rem; word-break: break-word; color: #444; }
.sub { font-size: .8rem; color: #57606a; }
.sub.err { color: #cf222e; }
.meta.ok { color: #1a7f37; }
.meta.err { color: #cf222e; }
.badge {
  display: inline-block;
  padding: .1rem .4rem;
  border-radius: 999px;
  font-size: .75rem;
  background: #eef1f4;
  margin-right: .25rem;
}
.badge.pending { background: #fff8c5; color: #9a6700; }
.badge.active { background: #dafbe1; color: #1a7f37; }
.badge.rejected { background: #ffebe9; color: #cf222e; }
.badge.dual { background: #ddf4ff; color: #0969da; }
.actions { display: flex; flex-wrap: wrap; gap: .3rem; }
.linkish {
  background: none;
  border: none;
  padding: 0;
  color: #0969da;
  cursor: pointer;
  font: inherit;
  text-align: left;
}
.empty { color: #888; text-align: center; padding: 1rem; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; margin-bottom: .75rem; }
@media (max-width: 720px) {
  .form-grid { grid-template-columns: 1fr; }
}
.state-banner { font-size: .85rem; color: #374151; line-height: 1.45; margin-bottom: .75rem; }
.hint-inline { color: #6b7280; font-family: inherit; font-size: .8rem; }
</style>
