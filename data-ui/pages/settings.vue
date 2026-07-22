<script setup lang="ts">
import type { AdminAuditStats, AdminMe, AdminSecurityPolicies } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Settings · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, defaultBase, hydrate, setApiBase } = useAdminSettings()
const draftBase = ref('')
const reloading = ref(false)
const reloadOut = ref('—')
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const busyProbe = ref(false)

/** UI31: gateway probe summary (soft-fail). */
const healthz = ref<string>('')
const version = ref('')
const me = ref<AdminMe | null>(null)
const policies = ref<AdminSecurityPolicies | null>(null)
const auditStats = ref<AdminAuditStats | null>(null)
const probeAt = ref('')

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

async function probeGateway() {
  busyProbe.value = true
  const base = apiBase.value
  try {
    const [hz, ver, who, pol, astats] = await Promise.all([
      $fetch<string | { status?: string }>(`${base.replace(/\/$/, '')}/healthz`, {
        responseType: 'text' as any,
      }).catch(async () => {
        try {
          return await $fetch(`${base.replace(/\/$/, '')}/healthz`)
        }
        catch {
          return null
        }
      }),
      api.version(base).catch(() => null),
      api.me(base).catch(() => null),
      api.securityPolicies(base).catch(() => null),
      api.auditStats(base).catch(() => null),
    ])
    if (typeof hz === 'string')
      healthz.value = hz.trim() || 'ok'
    else if (hz && typeof hz === 'object')
      healthz.value = (hz as any).status || JSON.stringify(hz)
    else
      healthz.value = hz == null ? 'unreachable' : 'ok'
    version.value = ver != null ? String(ver).trim() : '—'
    me.value = who
    policies.value = pol
    auditStats.value = astats
    probeAt.value = new Date().toLocaleTimeString()
    setStatus(
      healthz.value === 'unreachable'
        ? `Probe failed · ${probeAt.value}`
        : `Probe ok · ${probeAt.value}`,
      healthz.value === 'unreachable' ? 'error' : 'ok',
    )
  }
  catch (e: any) {
    healthz.value = 'unreachable'
    setStatus(e?.message || String(e), 'error')
  }
  finally {
    busyProbe.value = false
  }
}

onMounted(() => {
  hydrate()
  draftBase.value = apiBase.value
  probeGateway()
})

function saveBase() {
  setApiBase(draftBase.value)
  draftBase.value = apiBase.value
  setStatus('API base saved', 'ok')
  probeGateway()
}

function resetBase() {
  draftBase.value = defaultBase
  setApiBase(defaultBase)
  setStatus('API base reset', 'ok')
  probeGateway()
}

async function doReload() {
  reloading.value = true
  setStatus('Reloading config…')
  try {
    const body = await api.reload(apiBase.value)
    reloadOut.value = typeof body === 'string' ? body : JSON.stringify(body, null, 2)
    setStatus('Reload OK', 'ok')
    await probeGateway()
  }
  catch (err: any) {
    reloadOut.value = err?.data ? JSON.stringify(err.data, null, 2) : String(err?.message || err)
    setStatus(err?.message || String(err), 'error')
  }
  finally {
    reloading.value = false
  }
}
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <div>
        <h2 class="page-title">
          Settings
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
        :disabled="busyProbe"
        @click="probeGateway"
      >
        Probe gateway
      </button>
    </div>

    <section class="card">
      <h2>Admin API base</h2>
      <div class="field">
        <input
          v-model="draftBase"
          placeholder="http://127.0.0.1:8082"
          @keyup.enter="saveBase"
        >
        <button
          type="button"
          class="btn primary"
          @click="saveBase"
        >
          Save
        </button>
        <button
          type="button"
          class="btn"
          @click="resetBase"
        >
          Reset
        </button>
      </div>
      <p class="meta">
        Default from <code class="mono">NUXT_PUBLIC_ADMIN_API_BASE</code>.
        Stored in browser localStorage. UI31 probes
        <code class="mono">/healthz</code>, version, me, security-policies, audit stats after save.
      </p>
    </section>

    <section class="card">
      <h2>Gateway probe</h2>
      <dl class="kv">
        <div>
          <dt>healthz</dt>
          <dd class="mono">
            {{ healthz || '—' }}
          </dd>
        </div>
        <div>
          <dt>version</dt>
          <dd class="mono">
            {{ version || '—' }}
          </dd>
        </div>
        <div>
          <dt>admin subject</dt>
          <dd class="mono">
            {{ me?.subject || '—' }}
            <template v-if="me?.auth_method">
              · {{ me.auth_method }}
            </template>
          </dd>
        </div>
        <div>
          <dt>auth</dt>
          <dd class="mono">
            enabled={{ me?.auth_enabled ?? '—' }}
            · roles={{ (me?.roles || []).join(',') || '—' }}
          </dd>
        </div>
        <div>
          <dt>security</dt>
          <dd class="mono">
            <template v-if="policies">
              {{ policies.enabled ? 'on' : 'off' }}
              · pdp={{ policies.pdp_backend || policies.pdp?.backend || '—' }}
              · audit={{ policies.default_audit_level || '—' }}
              · state={{ policies.state?.backend || '—' }}
              <template v-if="policies.state?.backend === 'file'">
                · last-writer-wins / merge_strategy / crdt=false / mlock=false (not CRDT; vault RAM not mlock)
              </template>
            </template>
            <template v-else>
              —
            </template>
          </dd>
        </div>
        <div>
          <dt>audit stats</dt>
          <dd class="mono">
            <template v-if="auditStats">
              accepted={{ auditStats.accepted ?? '—' }}
              · written={{ auditStats.written ?? '—' }}
              · index_rows={{ auditStats.index_rows ?? '—' }}
              · prio_acc={{ auditStats.priority_accepted ?? '—' }}
            </template>
            <template v-else>
              —
            </template>
          </dd>
        </div>
        <div
          v-if="policies?.pdp"
          class="span-2"
        >
          <dt>pdp (F31/UI18)</dt>
          <dd class="mono">
            remote_configured={{ policies.pdp.remote_configured }}
            · timeout_ms={{ policies.pdp.remote_timeout_ms }}
            · fail_closed={{ policies.pdp.remote_fail_closed }}
            · token={{ policies.pdp.remote_token_configured ? 'yes' : 'no' }}
          </dd>
        </div>
      </dl>
      <p class="meta">
        Last probe: {{ probeAt || '—' }}. Secrets (remote_token / encrypt keys) are never returned.
      </p>
      <div class="row">
        <NuxtLink
          class="btn"
          to="/"
        >
          Overview
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
          to="/audit"
        >
          Audit
        </NuxtLink>
      </div>
    </section>

    <section class="card">
      <h2>Config reload</h2>
      <p class="meta">
        Calls <code class="mono">POST /admin/reload</code> on the gateway.
      </p>
      <button
        type="button"
        class="btn primary"
        :disabled="reloading"
        @click="doReload"
      >
        Reload config
      </button>
      <pre class="out">{{ reloadOut }}</pre>
    </section>

    <section class="card">
      <h2>Authentication</h2>
      <p class="meta">
        Optional password gate via
        <code class="mono">NUXT_PUBLIC_ADMIN_PASSWORD</code>.
        When set, all pages except <code class="mono">/login</code> require sign-in
        (localStorage session, 12h). Gateway Admin JWT/OIDC is separate from the UI password gate.
      </p>
    </section>
  </div>
</template>

<style scoped>
.page-toolbar { display: flex; justify-content: space-between; align-items: flex-start; gap: .75rem; margin-bottom: .5rem; }
.status-line { font-size: .88rem; color: #57606a; margin-top: .2rem; }
.status-line.ok { color: #1a7f37; }
.status-line.error { color: #cf222e; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .85rem; margin-bottom: .75rem; }
.card h2 { margin: 0 0 .5rem; font-size: 1rem; }
.field { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
.field input {
  flex: 1;
  min-width: 14rem;
  border: 1px solid #d0d7de;
  border-radius: 6px;
  padding: .4rem .55rem;
  font: inherit;
}
.meta { color: #57606a; font-size: .88rem; line-height: 1.45; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
.kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: .55rem 1rem;
  margin: 0 0 .65rem;
}
.kv > div { display: flex; flex-direction: column; gap: .15rem; }
.kv .span-2 { grid-column: 1 / -1; }
.kv dt { font-size: .8rem; color: #57606a; }
.kv dd { margin: 0; word-break: break-word; }
.row { display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .35rem; }
.out {
  margin: .75rem 0 0;
  padding: .6rem;
  background: #f6f8fa;
  border-radius: 6px;
  overflow: auto;
  font-size: .82rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
@media (max-width: 640px) {
  .kv { grid-template-columns: 1fr; }
}
</style>
