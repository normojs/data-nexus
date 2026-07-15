<script setup lang="ts">
definePageMeta({ layout: 'admin' })
useHead({ title: 'Settings · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, defaultBase, hydrate, setApiBase } = useAdminSettings()
const draftBase = ref('')
const reloading = ref(false)
const reloadOut = ref('—')
const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')

onMounted(() => {
  hydrate()
  draftBase.value = apiBase.value
})

function saveBase() {
  setApiBase(draftBase.value)
  draftBase.value = apiBase.value
  status.value = 'API base saved'
  statusKind.value = 'ok'
}

function resetBase() {
  draftBase.value = defaultBase
  setApiBase(defaultBase)
  status.value = 'API base reset'
  statusKind.value = 'ok'
}

async function doReload() {
  reloading.value = true
  status.value = 'Reloading config…'
  statusKind.value = ''
  try {
    const body = await api.reload(apiBase.value)
    reloadOut.value = typeof body === 'string' ? body : JSON.stringify(body, null, 2)
    status.value = 'Reload OK'
    statusKind.value = 'ok'
  }
  catch (err: any) {
    reloadOut.value = err?.data ? JSON.stringify(err.data, null, 2) : String(err?.message || err)
    status.value = err?.message || String(err)
    statusKind.value = 'error'
  }
  finally {
    reloading.value = false
  }
}
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <h2 class="page-title">
        Settings
      </h2>
    </div>
    <div
      class="status-line"
      :class="statusKind"
    >
      {{ status }}
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
        Stored in browser localStorage.
      </p>
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
      <pre style="margin-top: 12px">{{ reloadOut }}</pre>
    </section>

    <section class="card">
      <h2>Authentication</h2>
      <p class="meta">
        Optional password gate via
        <code class="mono">NUXT_PUBLIC_ADMIN_PASSWORD</code>.
        When set, all pages except <code class="mono">/login</code> require sign-in
        (localStorage session, 12h).
      </p>
    </section>
  </div>
</template>
