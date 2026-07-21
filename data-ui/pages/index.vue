<script setup lang="ts">
import type {
  AdminAuditStats,
  AdminEndpoint,
  AdminListener,
  AdminPool,
  AdminSecurityPolicies,
  AdminService,
  AdminSession,
  AdminTicket,
  AdminVaultLease,
} from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Overview · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()

const version = ref('—')
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const listeners = ref<AdminListener[]>([])
const services = ref<AdminService[]>([])
const endpoints = ref<AdminEndpoint[]>([])
const pools = ref<AdminPool[]>([])
const sessions = ref<AdminSession[]>([])
const auditStats = ref<AdminAuditStats | null>(null)
const policies = ref<AdminSecurityPolicies | null>(null)
const tickets = ref<AdminTicket[]>([])
const leases = ref<AdminVaultLease[]>([])

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

function isLeaseExpired(l: AdminVaultLease) {
  return Date.now() > (l.expires_at_unix_ms || 0)
}

const ticketCounts = computed(() => {
  const c = { pending: 0, active: 0, rejected: 0, total: tickets.value.length }
  for (const t of tickets.value) {
    const s = (t.status || '').toLowerCase()
    if (s === 'pending')
      c.pending++
    else if (s === 'active')
      c.active++
    else if (s === 'rejected')
      c.rejected++
  }
  return c
})

const leaseCounts = computed(() => {
  const c = { active: 0, expired: 0, revoked: 0, total: leases.value.length }
  for (const l of leases.value) {
    if (l.revoked)
      c.revoked++
    else if (isLeaseExpired(l))
      c.expired++
    else c.active++
  }
  return c
})

const protocolSessionBits = computed(() => {
  const m: Record<string, number> = {}
  for (const s of sessions.value) {
    const k = (s.frontend_protocol || '?').toLowerCase()
    m[k] = (m[k] || 0) + 1
  }
  return Object.entries(m)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([p, n]) => `${p}=${n}`)
    .join(' ')
})

const securityEnabled = computed(() => policies.value?.enabled === true)
const pdpBackend = computed(() => policies.value?.pdp_backend || policies.value?.pdp?.backend || '—')
const auditLevel = computed(() => policies.value?.default_audit_level || '—')
const windowRows = computed(() => policies.value?.streaming?.window_rows)
const stateBackend = computed(() => policies.value?.state?.backend || '—')

async function loadAll() {
  setStatus('Loading…')
  const base = apiBase.value
  try {
    const [ver, ls, svcs, eps, pls, sess, astats, pol, tix, vls] = await Promise.all([
      api.version(base).catch(() => 'Data Nexus'),
      api.listeners(base),
      api.services(base),
      api.endpoints(base),
      api.pools(base).catch(() => [] as AdminPool[]),
      api.sessions(base),
      api.auditStats(base).catch(() => null),
      api.securityPolicies(base).catch(() => null),
      api.tickets(100, base).catch(() => [] as AdminTicket[]),
      api.vaultLeases(base).catch(() => [] as AdminVaultLease[]),
    ])
    version.value = String(ver || 'Data Nexus').trim()
    listeners.value = ls
    services.value = svcs
    endpoints.value = eps
    pools.value = pls
    sessions.value = sess
    auditStats.value = astats
    policies.value = pol
    tickets.value = tix
    leases.value = vls
    const secBit = pol
      ? ` · security=${pol.enabled ? 'on' : 'off'} pdp=${pol.pdp_backend || '—'}`
      : ''
    const sessBit = protocolSessionBits.value ? ` · ${protocolSessionBits.value}` : ''
    setStatus(`Updated ${new Date().toLocaleTimeString()}${secBit}${sessBit}`, 'ok')
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
          Overview
        </h2>
        <div class="meta">
          {{ version }}
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
        <div
          v-if="protocolSessionBits"
          class="sub"
        >
          {{ protocolSessionBits }}
        </div>
      </div>
      <div class="stat-card">
        <div class="label">
          Pools
        </div>
        <div class="value">
          {{ pools.length }}
        </div>
      </div>
    </div>

    <h3 class="section-title">
      Security &amp; ops
      <span class="section-hint">UI28 · soft-fail if endpoints unavailable</span>
    </h3>
    <div class="stat-grid">
      <NuxtLink
        class="stat-card link-card"
        to="/policies"
      >
        <div class="label">
          Security
        </div>
        <div class="value">
          <span
            class="pill"
            :class="securityEnabled ? 'on' : 'off'"
          >{{ securityEnabled ? 'on' : 'off' }}</span>
        </div>
        <div class="sub mono">
          pdp={{ pdpBackend }}
          · audit={{ auditLevel }}
          <template v-if="windowRows != null">
            · window_rows={{ windowRows }}
          </template>
          · state={{ stateBackend }}
        </div>
      </NuxtLink>
      <NuxtLink
        class="stat-card link-card"
        to="/audit"
      >
        <div class="label">
          Audit accepted
        </div>
        <div class="value">
          {{ auditStats?.accepted ?? '—' }}
        </div>
        <div class="sub mono">
          written={{ auditStats?.written ?? '—' }}
          · dropped={{ auditStats?.dropped ?? '—' }}
          · prio_acc={{ auditStats?.priority_accepted ?? '—' }}
        </div>
      </NuxtLink>
      <NuxtLink
        class="stat-card link-card"
        to="/audit"
      >
        <div class="label">
          Audit index
        </div>
        <div class="value">
          {{ auditStats?.index_rows ?? '—' }}
        </div>
        <div class="sub mono">
          enabled={{ auditStats?.index_enabled ?? '—' }}
          · inserted={{ auditStats?.index_inserted ?? '—' }}
          · errors={{ auditStats?.index_errors ?? '—' }}
        </div>
      </NuxtLink>
      <NuxtLink
        class="stat-card link-card"
        to="/tickets"
      >
        <div class="label">
          Tickets
        </div>
        <div class="value">
          {{ ticketCounts.total }}
        </div>
        <div class="sub mono">
          pending={{ ticketCounts.pending }}
          · active={{ ticketCounts.active }}
          · rejected={{ ticketCounts.rejected }}
        </div>
      </NuxtLink>
      <NuxtLink
        class="stat-card link-card"
        to="/vault"
      >
        <div class="label">
          Vault leases
        </div>
        <div class="value">
          {{ leaseCounts.total }}
        </div>
        <div class="sub mono">
          active={{ leaseCounts.active }}
          · expired={{ leaseCounts.expired }}
          · revoked={{ leaseCounts.revoked }}
        </div>
      </NuxtLink>
    </div>

    <section class="card">
      <h2>Quick links</h2>
      <div class="admin-actions">
        <NuxtLink
          class="btn"
          to="/topology"
        >
          Topology
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/sessions"
        >
          Sessions
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/portal"
        >
          SQL Portal
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/audit"
        >
          Audit
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/tickets"
        >
          Tickets
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/vault"
        >
          Vault
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/policies"
        >
          Policies
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/cedar"
        >
          Cedar
        </NuxtLink>
        <NuxtLink
          class="btn"
          to="/settings"
        >
          Settings / Reload
        </NuxtLink>
      </div>
    </section>
  </div>
</template>

<style scoped>
.section-title {
  margin: 1rem 0 .5rem;
  font-size: 1rem;
  font-weight: 600;
  color: #24292f;
  display: flex;
  align-items: baseline;
  gap: .5rem;
}
.section-hint {
  font-size: .78rem;
  font-weight: 400;
  color: #6b7280;
}
.stat-card .sub {
  margin-top: .35rem;
  font-size: .75rem;
  color: #57606a;
  line-height: 1.35;
  word-break: break-word;
}
.stat-card .mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.link-card {
  text-decoration: none;
  color: inherit;
  transition: border-color .12s ease, box-shadow .12s ease;
}
.link-card:hover {
  border-color: #0969da;
  box-shadow: 0 0 0 1px rgba(9, 105, 218, .15);
}
.pill {
  display: inline-block;
  padding: .1rem .45rem;
  border-radius: 999px;
  font-size: .85rem;
  font-weight: 600;
}
.pill.on { background: #dafbe1; color: #1a7f37; }
.pill.off { background: #eef1f4; color: #57606a; }
</style>
