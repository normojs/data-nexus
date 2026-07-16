<script setup lang="ts">
import type { AdminAuditEvent } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Audit · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()
const events = ref<AdminAuditEvent[]>([])
const status = ref('')
const decision = ref('')
const service = ref('')

async function load() {
  status.value = 'Loading…'
  try {
    const res = await api.auditEvents({
      decision: decision.value || undefined,
      service: service.value || undefined,
      limit: 100,
    }, apiBase.value)
    events.value = res.events || []
    status.value = `${events.value.length} events`
  }
  catch (e: any) {
    status.value = e?.data?.message || e?.message || String(e)
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
          Audit
        </h2>
        <div class="meta">
          {{ status }}
        </div>
      </div>
      <div class="row">
        <input
          v-model="decision"
          class="input"
          placeholder="decision (deny/execute)"
        >
        <input
          v-model="service"
          class="input"
          placeholder="service"
        >
        <button
          type="button"
          class="btn"
          @click="load"
        >
          Refresh
        </button>
      </div>
    </div>
    <div class="card">
      <table class="table">
        <thead>
          <tr>
            <th>Decision</th>
            <th>Subject</th>
            <th>Service</th>
            <th>Outcome</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(e, i) in events"
            :key="e.event_id || i"
          >
            <td class="mono">
              {{ e.decision }}
            </td>
            <td>{{ e.subject_id }}</td>
            <td>{{ e.service }}</td>
            <td class="mono">
              {{ e.outcome }}
            </td>
            <td class="msg">
              {{ e.message || e.rule }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.input { border: 1px solid #d0d7de; border-radius: 6px; padding: .35rem .5rem; min-width: 10rem; }
.table { width: 100%; border-collapse: collapse; font-size: .9rem; }
.table th, .table td { border-bottom: 1px solid #eef1f4; padding: .45rem .4rem; text-align: left; vertical-align: top; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
.msg { max-width: 28rem; word-break: break-word; color: #444; }
.card { background: #fff; border: 1px solid #e6ebf0; border-radius: 10px; padding: .75rem; overflow: auto; }
</style>
