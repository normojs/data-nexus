<script setup lang="ts">
import type { AdminCedarStatus } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Cedar · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()
const { hydrateFromStorage } = useAdminAuth()

const status = ref<AdminCedarStatus | null>(null)
const message = ref('')
const messageKind = ref<'ok' | 'error' | ''>('')
const busy = ref(false)
const canReload = ref(false)
const reloadOut = ref('')

function setMessage(msg: string, kind: 'ok' | 'error' | '' = '') {
  message.value = msg
  messageKind.value = kind
}

function fmtMs(ms?: number) {
  if (!ms) return '—'
  try {
    return new Date(ms).toLocaleString()
  }
  catch {
    return String(ms)
  }
}

async function load() {
  setMessage('Loading Cedar status…')
  try {
    status.value = await api.cedarStatus(apiBase.value)
    if (status.value?.message && !status.value.ready) {
      setMessage(status.value.message, 'error')
    }
    else if (status.value?.ready) {
      setMessage(`Ready · epoch ${status.value.epoch}`, 'ok')
    }
    else if (status.value?.installed === false) {
      setMessage('Cedar store not installed (security.pdp.backend may be local)', '')
    }
    else {
      setMessage('Loaded', 'ok')
    }
  }
  catch (e: any) {
    setMessage(e?.data?.message || e?.message || String(e), 'error')
  }
}

async function reload() {
  busy.value = true
  setMessage('Reloading Cedar policies…')
  reloadOut.value = ''
  try {
    const info = await api.cedarReload(apiBase.value)
    reloadOut.value = JSON.stringify(info, null, 2)
    setMessage(
      info.swapped
        ? `Swapped · epoch ${info.epoch} · ${info.files} files / ${info.policy_count} policies`
        : `Unchanged · epoch ${info.epoch}`,
      'ok',
    )
    await load()
  }
  catch (e: any) {
    reloadOut.value = e?.data ? JSON.stringify(e.data, null, 2) : String(e?.message || e)
    setMessage(e?.data?.message || e?.message || String(e), 'error')
  }
  finally {
    busy.value = false
  }
}

onMounted(async () => {
  hydrate()
  hydrateFromStorage()
  try {
    const cfg = await api.authConfig(apiBase.value)
    if (cfg.enabled) {
      const me = await api.me(apiBase.value)
      canReload.value = me.permissions.includes('policy:write')
        || me.permissions.includes('config:reload')
        || me.roles.includes('admin')
        || me.roles.includes('operator')
    }
    else {
      canReload.value = true
    }
  }
  catch {
    canReload.value = true
  }
  await load()
})
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <div>
        <h2 class="page-title">
          Cedar PDP
        </h2>
        <div
          class="meta"
          :class="{ ok: messageKind === 'ok', err: messageKind === 'error' }"
        >
          {{ message }}
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
          v-if="canReload"
          type="button"
          class="btn primary"
          :disabled="busy"
          @click="reload"
        >
          Reload policies
        </button>
      </div>
    </div>

    <div class="card">
      <p class="hint">
        F26b: hot-reload re-reads <code class="mono">security.pdp.policy_dir</code> when
        <code class="mono">cache_epoch_reload=true</code>. Failed reloads keep the previous epoch
        (keep-old). Binary must be built with <code class="mono">--features security-cedar</code>.
      </p>
      <dl
        v-if="status"
        class="kv"
      >
        <div>
          <dt>Installed</dt>
          <dd class="mono">
            {{ status.installed ?? '—' }}
          </dd>
        </div>
        <div>
          <dt>Ready</dt>
          <dd class="mono">
            {{ status.ready ?? '—' }}
          </dd>
        </div>
        <div>
          <dt>Epoch</dt>
          <dd class="mono">
            {{ status.epoch ?? 0 }}
          </dd>
        </div>
        <div>
          <dt>Files</dt>
          <dd class="mono">
            {{ status.files ?? 0 }}
          </dd>
        </div>
        <div>
          <dt>Policies</dt>
          <dd class="mono">
            {{ status.policy_count ?? 0 }}
          </dd>
        </div>
        <div>
          <dt>Loaded at</dt>
          <dd class="mono">
            {{ fmtMs(status.loaded_at_unix_ms) }}
          </dd>
        </div>
        <div class="span-2">
          <dt>Source / policy_dir</dt>
          <dd class="mono">
            {{ status.source || '—' }}
          </dd>
        </div>
        <div v-if="status.pdp_backend">
          <dt>Config backend</dt>
          <dd class="mono">
            {{ status.pdp_backend }}
          </dd>
        </div>
        <div v-if="status.cache_epoch_reload != null">
          <dt>cache_epoch_reload</dt>
          <dd class="mono">
            {{ status.cache_epoch_reload }}
          </dd>
        </div>
        <div
          v-if="status.feature"
          class="span-2"
        >
          <dt>Feature</dt>
          <dd class="mono">
            {{ status.feature }} — {{ status.message }}
          </dd>
        </div>
      </dl>
      <div
        v-else
        class="empty"
      >
        No status yet.
      </div>
    </div>

    <div
      v-if="reloadOut"
      class="card"
    >
      <h3>Last reload response</h3>
      <pre class="out">{{ reloadOut }}</pre>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.hint { color: #57606a; font-size: .88rem; margin: 0 0 .75rem; }
.kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: .65rem 1rem;
  margin: 0;
}
.kv > div { display: flex; flex-direction: column; gap: .15rem; }
.kv .span-2 { grid-column: 1 / -1; }
.kv dt { font-size: .8rem; color: #57606a; }
.kv dd { margin: 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
.meta.ok { color: #1a7f37; }
.meta.err { color: #cf222e; }
.card {
  background: #fff;
  border: 1px solid #e6ebf0;
  border-radius: 10px;
  padding: .85rem;
  margin-bottom: .75rem;
}
.card h3 { margin: 0 0 .5rem; font-size: 1rem; }
.out {
  margin: 0;
  padding: .6rem;
  background: #f6f8fa;
  border-radius: 6px;
  overflow: auto;
  font-size: .82rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.empty { color: #888; }
@media (max-width: 640px) {
  .kv { grid-template-columns: 1fr; }
}
</style>
