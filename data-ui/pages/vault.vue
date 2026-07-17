<script setup lang="ts">
import type { AdminProject, AdminService, AdminVaultLease } from '~/composables/useAdminApi'

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

async function load() {
  setStatus('Loading vault…')
  const base = apiBase.value
  try {
    const [ls, projs, svcs] = await Promise.all([
      api.vaultLeases(base).catch(() => [] as AdminVaultLease[]),
      api.projects(base).catch(() => [] as AdminProject[]),
      api.services(base).catch(() => [] as AdminService[]),
    ])
    leases.value = ls
    projects.value = projs
    services.value = svcs
    if (!project.value) {
      project.value = projs[0]?.name || svcs[0]?.name || ''
      if (projs[0]?.environment)
        environment.value = projs[0].environment
    }
    setStatus(`${ls.length} leases · ${projs.length || svcs.length} projects/services`, 'ok')
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
  const reason = window.prompt('Revoke reason (optional)') ?? undefined
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

    <div class="card form-card">
      <h3>Issue lease</h3>
      <p class="hint">
        Short-lived portal credentials. Backend passwords stay in process memory and are
        <strong>never</strong> returned to the browser (H03).
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
      <h3>Active leases</h3>
      <table class="table">
        <thead>
          <tr>
            <th>Lease id</th>
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
            v-for="l in leases"
            :key="l.lease_id"
          >
            <td class="mono">
              {{ l.lease_id }}
              <span
                v-if="l.revoked"
                class="badge rejected"
              >revoked</span>
              <span
                v-else-if="isExpired(l)"
                class="badge pending"
              >expired</span>
            </td>
            <td>{{ l.project }} / {{ l.environment }}</td>
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
          <tr v-if="!leases.length">
            <td
              colspan="7"
              class="empty"
            >
              No vault leases.
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
</style>
