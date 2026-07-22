<script setup lang="ts">
import type {
  AdminPortalQueryResult,
  AdminProject,
  AdminSecurityPolicies,
  AdminService,
  AdminVaultLease,
} from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'SQL Portal · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()

const services = ref<AdminService[]>([])
const projects = ref<AdminProject[]>([])
const leases = ref<AdminVaultLease[]>([])
const service = ref('')
const sql = ref('SELECT 1 AS ok')
const maxRows = ref(100)
const leaseId = ref('')
const streamingCfg = ref<AdminSecurityPolicies['streaming'] | null>(null)
const result = ref<AdminPortalQueryResult | null>(null)
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
/** UI26: client-side lease picker filters (active by default). */
const leaseStatusFilter = ref<'active' | 'all' | 'expired' | 'revoked'>('active')
const leaseProjectFilter = ref('')
const leaseServiceFilter = ref('')
const projectListFilter = ref('')

function truncatedHint(res: AdminPortalQueryResult): string {
  if (!res.truncated)
    return ''
  const client = maxRows.value || undefined
  const policy = streamingCfg.value?.max_rows ?? undefined
  const bits: string[] = []
  if (client != null)
    bits.push(`client max_rows=${client}`)
  if (policy != null)
    bits.push(`policy max_rows=${policy}`)
  // Effective cap is the min of client request and policy when both set.
  if (client != null && policy != null)
    bits.push(`effective≤${Math.min(client, policy)}`)
  else if (client != null)
    bits.push(`effective≤${client}`)
  else if (policy != null)
    bits.push(`effective≤${policy}`)
  return bits.length ? `truncated (${bits.join(', ')})` : 'truncated'
}

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

function isLeaseExpired(l: AdminVaultLease) {
  return Date.now() > (l.expires_at_unix_ms || 0)
}

function leaseStatus(l: AdminVaultLease): 'active' | 'expired' | 'revoked' {
  if (l.revoked)
    return 'revoked'
  if (isLeaseExpired(l))
    return 'expired'
  return 'active'
}

const filteredProjects = computed(() => {
  const q = projectListFilter.value.trim().toLowerCase()
  if (!q)
    return projects.value
  return projects.value.filter(p =>
    (p.name || '').toLowerCase().includes(q)
    || (p.environment || '').toLowerCase().includes(q)
    || (p.service || '').toLowerCase().includes(q),
  )
})

const filteredLeases = computed(() => {
  const st = leaseStatusFilter.value
  const proj = leaseProjectFilter.value.trim().toLowerCase()
  const svc = leaseServiceFilter.value.trim().toLowerCase()
  return leases.value.filter((l) => {
    const ls = leaseStatus(l)
    if (st !== 'all' && ls !== st)
      return false
    if (proj && !(l.project || '').toLowerCase().includes(proj)
      && !(l.environment || '').toLowerCase().includes(proj))
      return false
    if (svc && !(l.service || '').toLowerCase().includes(svc)
      && !(l.endpoint || '').toLowerCase().includes(svc))
      return false
    return true
  })
})

const leaseStatusCounts = computed(() => {
  const c = { active: 0, expired: 0, revoked: 0 }
  for (const l of leases.value)
    c[leaseStatus(l)]++
  return c
})

function pickLease(l: AdminVaultLease) {
  leaseId.value = l.lease_id
  if (l.service)
    service.value = l.service
  setStatus(`Selected lease ${l.lease_id} · service=${l.service}`, 'ok')
}

function pickProject(p: AdminProject) {
  if (p.service)
    service.value = p.service
  leaseProjectFilter.value = p.name || ''
  setStatus(`Service=${p.service} from project ${p.name}/${p.environment}`, 'ok')
}

function clearLeaseFilters() {
  leaseStatusFilter.value = 'active'
  leaseProjectFilter.value = ''
  leaseServiceFilter.value = ''
}

async function loadMeta() {
  const base = apiBase.value
  const [svcs, projs, ls, policies] = await Promise.all([
    api.services(base),
    api.projects(base).catch(() => [] as AdminProject[]),
    api.vaultLeases(base).catch(() => [] as AdminVaultLease[]),
    api.securityPolicies(base).catch(() => null),
  ])
  services.value = svcs
  projects.value = projs
  leases.value = ls
  streamingCfg.value = policies?.streaming ?? null
  if (!service.value && svcs[0])
    service.value = svcs[0].name
  // Drop selected lease if it disappeared after prune/revoke.
  if (leaseId.value && !ls.some(l => l.lease_id === leaseId.value))
    leaseId.value = ''
}

async function issueLease() {
  if (!service.value) return
  setStatus('Issuing vault lease…')
  try {
    const lease = await api.issueVaultLease({
      project: service.value,
      environment: 'dev',
      ttl_secs: 900,
    }, apiBase.value)
    leaseId.value = lease.lease_id
    await loadMeta()
    setStatus(`Lease ${lease.lease_id} (no password returned)`, 'ok')
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
}

async function runQuery() {
  setStatus('Running via PEP…')
  result.value = null
  try {
    const res = await api.portalQuery({
      service: service.value,
      sql: sql.value,
      lease_id: leaseId.value || undefined,
      max_rows: maxRows.value || undefined,
    }, apiBase.value)
    result.value = res
    const streamBit = res.stream ? ` · stream=${res.stream}` : ''
    const winBit =
      res.window_rows != null ? ` · window_rows=${res.window_rows}` : ''
    setStatus(
      `OK · ${res.row_count} rows${res.truncated ? ` (${truncatedHint(res)})` : ''}${streamBit}${winBit}`,
      'ok',
    )
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
}

async function exportResult(format: 'csv' | 'ndjson' | 'json') {
  if (!service.value || !sql.value.trim()) {
    setStatus('Service and SQL are required for export', 'error')
    return
  }
  setStatus(`Exporting ${format} via PEP…`)
  try {
    const { blob, stream } = await api.portalExport({
      service: service.value,
      sql: sql.value,
      lease_id: leaseId.value || undefined,
      max_rows: maxRows.value || 5000,
      format,
    }, apiBase.value)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `portal-export.${format === 'ndjson' ? 'ndjson' : format}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    const streamBit = stream ? ` · stream=${stream}` : ''
    setStatus(
      `Exported ${format}${streamBit} (PEP + max_rows; not full-result dump)`,
      'ok',
    )
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
}

onMounted(async () => {
  hydrate()
  try {
    await loadMeta()
    setStatus('Ready — queries execute through Local PDP + backend (never direct DB)', 'ok')
  }
  catch (e: any) {
    setStatus(e?.message || String(e), 'error')
  }
})
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <div>
        <h2 class="page-title">
          SQL Portal
        </h2>
        <div
          class="meta"
          :class="statusKind"
        >
          {{ status }}
        </div>
      </div>
    </div>

    <div class="grid">
      <section class="card">
        <h3>Context</h3>
        <label class="field">
          <span>Service (PEP target)</span>
          <select v-model="service">
            <option
              v-for="s in services"
              :key="s.name"
              :value="s.name"
            >
              {{ s.name }} ({{ s.backend_protocol }})
            </option>
          </select>
        </label>
        <label class="field">
          <span>Max rows</span>
          <input
            v-model.number="maxRows"
            type="number"
            min="1"
          >
          <span
            v-if="streamingCfg"
            class="field-hint mono"
          >
            gateway window_rows={{ streamingCfg.window_rows }}
            · passthrough={{ streamingCfg.passthrough }}
            <template v-if="streamingCfg.max_rows != null">
              · policy max_rows={{ streamingCfg.max_rows }}
            </template>
            · peak=logical window (not RSS)
          </span>
        </label>
        <label class="field">
          <span>Vault lease id (optional)</span>
          <input
            v-model="leaseId"
            placeholder="issue lease first"
          >
        </label>
        <div class="actions">
          <button
            type="button"
            class="btn"
            @click="issueLease"
          >
            Issue vault lease
          </button>
          <button
            type="button"
            class="btn primary"
            @click="runQuery"
          >
            Run SQL
          </button>
          <button
            type="button"
            class="btn"
            @click="exportResult('csv')"
          >
            Export CSV
          </button>
          <button
            type="button"
            class="btn"
            @click="exportResult('ndjson')"
          >
            Export NDJSON
          </button>
        </div>
                <p class="hint">
          Leases never include backend passwords. SQL is authorized by Local PDP and executed via gateway backends only.
          Exports use the same PEP path (<code class="mono">csv|ndjson|json</code>).
          Multi-row SELECT should report <code class="mono">stream=backend_window</code>; non-SELECT Complete fallbacks use
          <code class="mono">stream=chunked</code> (HTTP windows; backend ResultSet may already be materialized).
          CSV exposes the pin via <code class="mono">x-data-nexus-window-rows</code> (no JSON meta).
          Simple-query <code class="mono">DECLARE/FETCH/CLOSE</code> is a <strong>process-local</strong> named cursor
          (<code class="mono">sql_cursor_*</code> metrics): not a backend SQL <code class="mono">WITH HOLD</code> server cursor;
          disconnect ends the cursor even with <code class="mono">WITH HOLD</code> in the text.
        </p>

        <div
          v-if="projects.length"
          class="mini"
        >
          <strong>Projects</strong>
          <div class="row mini-filters">
            <input
              v-model="projectListFilter"
              class="mini-input"
              placeholder="Filter projects…"
              aria-label="Filter projects"
            >
            <span class="hint-inline">
              {{ filteredProjects.length }}/{{ projects.length }}
            </span>
          </div>
          <ul>
            <li
              v-for="p in filteredProjects"
              :key="`${p.name}-${p.environment}`"
            >
              <button
                type="button"
                class="linkish"
                :title="`Use service ${p.service}`"
                @click="pickProject(p)"
              >
                {{ p.name }}/{{ p.environment }}
              </button>
              → {{ p.service }}
            </li>
            <li
              v-if="!filteredProjects.length"
              class="empty-li"
            >
              No projects match.
            </li>
          </ul>
        </div>
        <div
          v-if="leases.length"
          class="mini"
        >
          <strong>Vault leases</strong>
          <div class="row mini-filters">
            <select
              v-model="leaseStatusFilter"
              class="mini-input"
              aria-label="Filter lease status"
            >
              <option value="active">
                active ({{ leaseStatusCounts.active }})
              </option>
              <option value="expired">
                expired ({{ leaseStatusCounts.expired }})
              </option>
              <option value="revoked">
                revoked ({{ leaseStatusCounts.revoked }})
              </option>
              <option value="all">
                all ({{ leases.length }})
              </option>
            </select>
            <input
              v-model="leaseProjectFilter"
              class="mini-input"
              placeholder="project/env…"
              aria-label="Filter lease project"
            >
            <input
              v-model="leaseServiceFilter"
              class="mini-input"
              placeholder="service…"
              aria-label="Filter lease service"
            >
            <button
              type="button"
              class="btn"
              @click="clearLeaseFilters"
            >
              Reset
            </button>
            <span class="hint-inline">
              {{ filteredLeases.length }}/{{ leases.length }}
            </span>
          </div>
          <p class="hint mini-hint">
            UI26: default shows active leases only. Click a lease to fill lease id and service.
            Passwords never appear here.
          </p>
          <ul>
            <li
              v-for="l in filteredLeases"
              :key="l.lease_id"
            >
              <button
                type="button"
                class="linkish"
                :class="{ selected: leaseId === l.lease_id }"
                :disabled="leaseStatus(l) === 'revoked'"
                @click="pickLease(l)"
              >
                {{ l.lease_id }}
              </button>
              <span
                class="lease-st"
                :class="leaseStatus(l)"
              >{{ leaseStatus(l) }}</span>
              · {{ l.project }}/{{ l.environment }} · {{ l.service }} · {{ l.username }}@{{ l.address }}
            </li>
            <li
              v-if="!filteredLeases.length"
              class="empty-li"
            >
              No leases match filters.
            </li>
          </ul>
        </div>
      </section>

      <section class="card grow">
        <h3>SQL</h3>
        <textarea
          v-model="sql"
          class="sql"
          rows="8"
          spellcheck="false"
        />
        <div
          v-if="result"
          class="result"
        >
          <div class="meta">
            decision={{ result.decision }} · rows={{ result.row_count }}
            <span v-if="result.truncated"> · {{ truncatedHint(result) }}</span>
            <span
              v-if="result.stream"
              class="stream-badge"
              :class="{
                bw: result.stream === 'backend_window',
                ch: result.stream === 'chunked',
              }"
            >
              · stream={{ result.stream }}
            </span>
            <span v-if="result.window_rows != null">
              · window_rows={{ result.window_rows }}
            </span>
          </div>
          <table class="table">
            <thead>
              <tr>
                <th
                  v-for="c in result.columns"
                  :key="c"
                >
                  {{ c }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(row, ri) in result.rows"
                :key="ri"
              >
                <td
                  v-for="(cell, ci) in row"
                  :key="ci"
                  class="mono"
                >
                  {{ cell === null ? 'NULL' : cell }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.grid { display: grid; grid-template-columns: 22rem 1fr; gap: 1rem; }
@media (max-width: 960px) { .grid { grid-template-columns: 1fr; } }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: 1rem; }
.grow { min-width: 0; }
.field { display: flex; flex-direction: column; gap: .25rem; margin-bottom: .75rem; font-size: .9rem; }
.field input, .field select, .sql {
  border: 1px solid #d0d7de; border-radius: 6px; padding: .45rem .55rem; font: inherit;
}
.sql { width: 100%; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem; }
.actions { display: flex; gap: .5rem; flex-wrap: wrap; margin: .5rem 0 1rem; }
.btn.primary { background: #0969da; color: #fff; border-color: #0969da; }
.hint { color: #57606a; font-size: .85rem; line-height: 1.4; }
.mini { margin-top: 1rem; font-size: .85rem; }
.mini ul { margin: .35rem 0 0; padding-left: 1.1rem; }
.linkish { background: none; border: none; color: #0969da; cursor: pointer; padding: 0; font: inherit; }
.table { width: 100%; border-collapse: collapse; margin-top: .5rem; font-size: .9rem; }
.table th, .table td { border-bottom: 1px solid #eef1f4; padding: .4rem; text-align: left; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.meta.ok { color: #1a7f37; }
.meta.error { color: #cf222e; }
.field-hint { display: block; margin-top: .25rem; font-size: .75rem; color: #6b7280; }
.stream-badge.bw { color: #047857; font-weight: 600; }
.stream-badge.ch { color: #b45309; font-weight: 600; }
.row { display: flex; gap: .4rem; align-items: center; flex-wrap: wrap; }
.mini-filters { margin: .35rem 0; }
.mini-input {
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: .25rem .4rem;
  font: inherit;
  font-size: .82rem;
  min-width: 6.5rem;
  max-width: 9rem;
}
.hint-inline { color: #6b7280; font-size: .78rem; }
.mini-hint { margin: .25rem 0 .35rem; }
.empty-li { color: #888; list-style: none; margin-left: -1.1rem; }
.lease-st {
  display: inline-block;
  padding: .05rem .35rem;
  border-radius: 999px;
  font-size: .72rem;
  margin: 0 .15rem;
}
.lease-st.active { background: #dafbe1; color: #1a7f37; }
.lease-st.expired { background: #fff8c5; color: #9a6700; }
.lease-st.revoked { background: #ffebe9; color: #cf222e; }
.linkish.selected { font-weight: 700; text-decoration: underline; }
.linkish:disabled { color: #888; cursor: default; }
</style>
