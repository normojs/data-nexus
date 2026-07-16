<script setup lang="ts">
import type {
  AdminPortalQueryResult,
  AdminProject,
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
const result = ref<AdminPortalQueryResult | null>(null)
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

async function loadMeta() {
  const base = apiBase.value
  const [svcs, projs, ls] = await Promise.all([
    api.services(base),
    api.projects(base).catch(() => [] as AdminProject[]),
    api.vaultLeases(base).catch(() => [] as AdminVaultLease[]),
  ])
  services.value = svcs
  projects.value = projs
  leases.value = ls
  if (!service.value && svcs[0])
    service.value = svcs[0].name
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
    setStatus(`OK · ${res.row_count} rows${res.truncated ? ' (truncated)' : ''}`, 'ok')
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
        </div>
        <p class="hint">
          Leases never include backend passwords. SQL is authorized by Local PDP and executed via gateway backends only.
        </p>
        <div
          v-if="projects.length"
          class="mini"
        >
          <strong>Projects</strong>
          <ul>
            <li
              v-for="p in projects"
              :key="`${p.name}-${p.environment}`"
            >
              {{ p.name }}/{{ p.environment }} → {{ p.service }}
            </li>
          </ul>
        </div>
        <div
          v-if="leases.length"
          class="mini"
        >
          <strong>Active leases</strong>
          <ul>
            <li
              v-for="l in leases"
              :key="l.lease_id"
            >
              <button
                type="button"
                class="linkish"
                @click="leaseId = l.lease_id"
              >
                {{ l.lease_id }}
              </button>
              · {{ l.service }} · {{ l.username }}@{{ l.address }}
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
            <span v-if="result.truncated"> · truncated</span>
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
</style>
