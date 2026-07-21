<script setup lang="ts">
import type { AdminProject, AdminSecurityPolicies, AdminService, AdminVaultLease } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Vault · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()

const leases = ref<AdminVaultLease[]>([])
const projects = ref<AdminProject[]>([])
const services = ref<AdminService[]>([])
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const busy = ref(false)

const project = ref('')
const environment = ref('dev')
const ttlSecs = ref(900)
const policyState = ref<AdminSecurityPolicies['state'] | null>(null)
/** UI24: client-side lease list filters (API returns full page). */
const statusFilter = ref('')
const projectFilter = ref('')
const envFilter = ref('')
const serviceFilter = ref('')

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

function isExpired(l: AdminVaultLease) {
  return Date.now() > (l.expires_at_unix_ms || 0)
}

/** active | expired | revoked — revoked wins over expired. */
function leaseStatus(l: AdminVaultLease): 'active' | 'expired' | 'revoked' {
  if (l.revoked)
    return 'revoked'
  if (isExpired(l))
    return 'expired'
  return 'active'
}

const filteredLeases = computed(() => {
  const st = statusFilter.value.trim().toLowerCase()
  const proj = projectFilter.value.trim().toLowerCase()
  const env = envFilter.value.trim().toLowerCase()
  const svc = serviceFilter.value.trim().toLowerCase()
  return leases.value.filter((l) => {
    if (st && leaseStatus(l) !== st)
      return false
    if (proj && !(l.project || '').toLowerCase().includes(proj))
      return false
    if (env && !(l.environment || '').toLowerCase().includes(env))
      return false
    if (svc && !(l.service || '').toLowerCase().includes(svc)
      && !(l.endpoint || '').toLowerCase().includes(svc))
      return false
    return true
  })
})

const statusCounts = computed(() => {
  const c = { active: 0, expired: 0, revoked: 0 }
  for (const l of leases.value) {
    const s = leaseStatus(l)
    c[s]++
  }
  return c
})

function clearListFilters() {
  statusFilter.value = ''
  projectFilter.value = ''
  envFilter.value = ''
  serviceFilter.value = ''
}

function setStatusFilter(s: string) {
  statusFilter.value = statusFilter.value === s ? '' : s
}

function setProjectEnvFromLease(l: AdminVaultLease) {
  projectFilter.value = l.project || ''
  envFilter.value = l.environment || ''
}

async function load() {
  setStatus('Loading vault…')
  const base = apiBase.value
  try {
    const [ls, projs, svcs, policies] = await Promise.all([
      api.vaultLeases(base).catch(() => [] as AdminVaultLease[]),
      api.projects(base).catch(() => [] as AdminProject[]),
      api.services(base).catch(() => [] as AdminService[]),
      api.securityPolicies(base).catch(() => null),
    ])
    leases.value = ls
    projects.value = projs
    services.value = svcs
    policyState.value = policies?.state ?? null
    if (!project.value) {
      project.value = projs[0]?.name || svcs[0]?.name || ''
      if (projs[0]?.environment)
        environment.value = projs[0].environment
    }
    const st = policyState.value
    const stateBit = st
      ? ` · state=${st.backend}${st.vault_encrypt_configured ? '+enc' : ''}`
      : ''
    const counts = statusCounts.value
    const countBit = ` · active=${counts.active} expired=${counts.expired} revoked=${counts.revoked}`
    setStatus(
      `${ls.length} leases${countBit} · ${projs.length || svcs.length} projects/services${stateBit}`,
      'ok',
    )
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
}

async function issue() {
  if (!project.value.trim()) {
    setStatus('project is required', 'error')
    return
  }
  busy.value = true
  setStatus('Issuing lease…')
  try {
    const lease = await api.issueVaultLease({
      project: project.value.trim(),
      environment: environment.value.trim() || 'dev',
      ttl_secs: ttlSecs.value || 900,
    }, apiBase.value)
    setStatus(`Lease ${lease.lease_id} (password never returned)`, 'ok')
    await load()
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

async function renew(id: string) {
  busy.value = true
  try {
    const lease = await api.renewVaultLease(id, { ttl_secs: ttlSecs.value || 900 }, apiBase.value)
    setStatus(`Renewed ${lease.lease_id}`, 'ok')
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
  const raw = window.prompt('Revoke reason (optional)')
  if (raw === null)
    return
  const reason = raw.trim() || undefined
  busy.value = true
  try {
    const lease = await api.revokeVaultLease(id, { reason }, apiBase.value)
    setStatus(`Revoked ${lease.lease_id}`, 'ok')
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
    const r = await api.pruneVaultLeases(apiBase.value)
    setStatus(`Pruned ${r.removed ?? 0} expired leases`, 'ok')
    await load()
  }
  catch (e: any) {
    setStatus(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

function copyToken(token: string) {
  if (import.meta.client && navigator.clipboard) {
    navigator.clipboard.writeText(token).then(() => setStatus('Access token copied', 'ok'))
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
          Vault
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
      · vault_enc={{ policyState.vault_encrypt_configured ? 'yes' : 'no' }}
      · ticket_enc={{ policyState.ticket_encrypt_configured ? 'yes' : 'no' }}
      · poll_ms={{ policyState.policy_poll_ms }}
      <template v-if="policyState.backend === 'file'">
        · vault={{ policyState.vault_path || '—' }}
      </template>
      <span class="hint-inline"> (keys never returned; file backend last-writer-wins, not CRDT)</span>
    </div>

    <div class="card form-card">
      <h3>Issue lease</h3>
      <p class="hint">
        Short-lived portal credentials. Backend passwords stay in process memory (revoke/Drop zeroize; not mlock) and are
        <strong>never</strong> returned to the browser (H03/H05).
      </p>
      <div class="form-grid">
        <label>
          <span>Project (or service name)</span>
          <input
            v-model="project"
            class="input"
            list="vault-projects"
            placeholder="orders"
          >
          <datalist id="vault-projects">
            <option
              v-for="p in projects"
              :key="`${p.name}/${p.environment}`"
              :value="p.name"
            >
              {{ p.environment }} → {{ p.service }}
            </option>
            <option
              v-for="s in services"
              :key="s.name"
              :value="s.name"
            />
          </datalist>
        </label>
        <label>
          <span>Environment</span>
          <input
            v-model="environment"
            class="input"
            placeholder="dev"
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
      </div>
      <div class="row">
        <button
          type="button"
          class="btn primary"
          :disabled="busy"
          @click="issue"
        >
          Issue lease
        </button>
      </div>
    </div>

    <div
      v-if="projects.length"
      class="card"
    >
      <h3>Projects</h3>
      <table class="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Env</th>
            <th>Service</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="p in projects"
            :key="`${p.name}/${p.environment}`"
          >
            <td class="mono">
              {{ p.name }}
            </td>
            <td>{{ p.environment }}</td>
            <td class="mono">
              {{ p.service }}
            </td>
            <td>{{ p.description || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>Leases</h3>
      <div class="row list-filters">
        <label>
          <span class="sr">Status</span>
          <select
            v-model="statusFilter"
            class="input"
            aria-label="Filter by lease status"
          >
            <option value="">
              All statuses
            </option>
            <option value="active">
              active ({{ statusCounts.active }})
            </option>
            <option value="expired">
              expired ({{ statusCounts.expired }})
            </option>
            <option value="revoked">
              revoked ({{ statusCounts.revoked }})
            </option>
          </select>
        </label>
        <label>
          <span class="sr">Project</span>
          <input
            v-model="projectFilter"
            class="input"
            placeholder="Filter project…"
            aria-label="Filter by project"
          >
        </label>
        <label>
          <span class="sr">Environment</span>
          <input
            v-model="envFilter"
            class="input"
            placeholder="Filter env…"
            aria-label="Filter by environment"
          >
        </label>
        <label>
          <span class="sr">Service</span>
          <input
            v-model="serviceFilter"
            class="input"
            placeholder="Filter service/endpoint…"
            aria-label="Filter by service"
          >
        </label>
        <button
          type="button"
          class="btn"
          :disabled="!statusFilter && !projectFilter && !envFilter && !serviceFilter"
          @click="clearListFilters"
        >
          Clear filters
        </button>
        <span class="hint-inline">
          showing {{ filteredLeases.length }} / {{ leases.length }}
          <template v-if="statusFilter || projectFilter || envFilter || serviceFilter">
            (client-side)
          </template>
        </span>
      </div>
      <p class="hint">
        UI24: status / project / env / service filters are client-side over the loaded
        page. Backend password is never returned; Copy token is the portal access token only.
      </p>
      <div class="row status-chips">
        <button
          type="button"
          class="chip"
          :class="{ on: statusFilter === 'active' }"
          @click="setStatusFilter('active')"
        >
          active {{ statusCounts.active }}
        </button>
        <button
          type="button"
          class="chip"
          :class="{ on: statusFilter === 'expired' }"
          @click="setStatusFilter('expired')"
        >
          expired {{ statusCounts.expired }}
        </button>
        <button
          type="button"
          class="chip"
          :class="{ on: statusFilter === 'revoked' }"
          @click="setStatusFilter('revoked')"
        >
          revoked {{ statusCounts.revoked }}
        </button>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>Lease id</th>
            <th>Status</th>
            <th>Project / Env</th>
            <th>Service · Endpoint</th>
            <th>User</th>
            <th>Expires</th>
            <th>Token</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="l in filteredLeases"
            :key="l.lease_id"
          >
            <td class="mono">
              {{ l.lease_id }}
            </td>
            <td>
              <button
                type="button"
                class="badge linkish-badge"
                :class="leaseStatus(l)"
                :title="`Filter status=${leaseStatus(l)}`"
                @click="setStatusFilter(leaseStatus(l))"
              >
                {{ leaseStatus(l) }}
              </button>
            </td>
            <td>
              <button
                type="button"
                class="linkish"
                :title="`Filter project=${l.project} env=${l.environment}`"
                @click="setProjectEnvFromLease(l)"
              >
                {{ l.project }} / {{ l.environment }}
              </button>
            </td>
            <td>
              <div class="mono">
                {{ l.service }}
              </div>
              <div class="sub mono">
                {{ l.endpoint }} · {{ l.protocol }} · {{ l.address }}
              </div>
            </td>
            <td class="mono">
              {{ l.username }}
            </td>
            <td class="mono">
              {{ fmtMs(l.expires_at_unix_ms) }}
            </td>
            <td>
              <button
                type="button"
                class="btn"
                :disabled="!!l.revoked"
                @click="copyToken(l.access_token)"
              >
                Copy token
              </button>
            </td>
            <td class="actions">
              <button
                type="button"
                class="btn"
                :disabled="busy || !!l.revoked"
                @click="renew(l.lease_id)"
              >
                Renew
              </button>
              <button
                type="button"
                class="btn"
                :disabled="busy || !!l.revoked"
                @click="revoke(l.lease_id)"
              >
                Revoke
              </button>
            </td>
          </tr>
          <tr v-if="!filteredLeases.length">
            <td
              colspan="8"
              class="empty"
            >
              {{ leases.length ? 'No leases match filters.' : 'No vault leases.' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.form-card h3, .card h3 { margin: 0 0 .35rem; font-size: 1rem; }
.hint { color: #57606a; font-size: .88rem; margin: 0 0 .75rem; }
.form-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: .65rem .75rem;
  margin-bottom: .75rem;
}
.form-grid label { display: flex; flex-direction: column; gap: .25rem; font-size: .85rem; color: #444; }
.input {
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: .35rem .5rem;
  font: inherit;
}
.table { width: 100%; border-collapse: collapse; font-size: .88rem; }
.table th, .table td {
  border-bottom: 1px solid #eef1f4;
  padding: .45rem .4rem;
  text-align: left;
  vertical-align: top;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
.sub { font-size: .8rem; color: #57606a; }
.meta.ok { color: #1a7f37; }
.meta.err { color: #cf222e; }
.badge {
  display: inline-block;
  padding: .1rem .4rem;
  border-radius: 999px;
  font-size: .75rem;
  margin-left: .25rem;
}
.badge.pending { background: #fff8c5; color: #9a6700; }
.badge.rejected { background: #ffebe9; color: #cf222e; }
.actions { display: flex; flex-wrap: wrap; gap: .3rem; }
.empty { color: #888; text-align: center; padding: 1rem; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; margin-bottom: .75rem; }
@media (max-width: 720px) {
  .form-grid { grid-template-columns: 1fr; }
}
.state-banner {
  margin-bottom: .75rem;
  font-size: .85rem;
  color: #374151;
  line-height: 1.45;
}
.hint-inline {
  color: #6b7280;
  font-family: inherit;
  font-size: .8rem;
}
.list-filters { margin-bottom: .5rem; gap: .55rem; }
.list-filters label { display: flex; flex-direction: column; gap: .15rem; min-width: 8rem; }
.list-filters .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
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
.badge.active { background: #dafbe1; color: #1a7f37; }
.badge.expired { background: #fff8c5; color: #9a6700; }
.badge.revoked { background: #ffebe9; color: #cf222e; }
button.badge {
  border: 0;
  cursor: pointer;
  font: inherit;
  margin-left: 0;
}
button.badge:hover { filter: brightness(0.97); text-decoration: underline; }
.linkish {
  background: none;
  border: none;
  padding: 0;
  color: #0969da;
  cursor: pointer;
  font: inherit;
  text-align: left;
}
</style>
