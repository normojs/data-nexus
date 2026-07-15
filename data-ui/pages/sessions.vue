<script setup lang="ts">
import type { AdminSession } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Sessions · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate: hydrateSettings } = useAdminSettings()

const status = ref('')
const statusKind = ref<'ok' | 'error' | ''>('')
const sessions = ref<AdminSession[]>([])

function setStatus(msg: string, kind: 'ok' | 'error' | '' = '') {
  status.value = msg
  statusKind.value = kind
}

async function loadAll() {
  setStatus('Loading…')
  try {
    sessions.value = await api.sessions(apiBase.value)
    setStatus(`Updated ${new Date().toLocaleTimeString()}`, 'ok')
  }
  catch (err: any) {
    setStatus(err?.data?.message || err?.message || String(err), 'error')
  }
}

let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  hydrateSettings()
  loadAll()
  timer = setInterval(loadAll, 10000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="page">
    <div class="page-toolbar">
      <h2 class="page-title">
        Sessions
      </h2>
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

    <section class="card">
      <h2>Active sessions ({{ sessions.length }})</h2>
      <p
        v-if="!sessions.length"
        class="empty"
      >
        empty
      </p>
      <table v-else>
        <thead>
          <tr>
            <th>id</th>
            <th>listener</th>
            <th>frontend</th>
            <th>peer</th>
            <th>database</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in sessions"
            :key="row.id"
          >
            <td class="mono">
              {{ row.id }}
            </td>
            <td>{{ row.listener }}</td>
            <td><span class="pill">{{ row.frontend_protocol }}</span></td>
            <td class="mono">
              {{ row.peer_addr || '—' }}
            </td>
            <td>{{ row.database || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
