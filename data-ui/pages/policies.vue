<script setup lang="ts">
import type { AdminSecurityPolicies } from '~/composables/useAdminApi'

definePageMeta({ layout: 'admin' })
useHead({ title: 'Policies · Data Nexus Admin' })

const api = useAdminApi()
const { apiBase, hydrate } = useAdminSettings()

const policy = ref<AdminSecurityPolicies | null>(null)
const message = ref('')
const messageKind = ref<'ok' | 'error' | ''>('')
const filter = ref('')

function setMessage(msg: string, kind: 'ok' | 'error' | '' = '') {
  message.value = msg
  messageKind.value = kind
}

function joinList(v?: string[] | null) {
  if (!v || !v.length) return '—'
  return v.join(', ')
}

function matchesFilter(parts: Array<string | undefined | null>) {
  const q = filter.value.trim().toLowerCase()
  if (!q) return true
  return parts.some(p => (p || '').toLowerCase().includes(q))
}

const filteredRules = computed(() =>
  (policy.value?.rules || []).filter(r =>
    matchesFilter([r.name, r.effect, joinList(r.actions), joinList(r.tables), joinList(r.columns), joinList(r.subjects), r.row_filter]),
  ),
)

const filteredMasks = computed(() =>
  (policy.value?.mask_rules || []).filter(r =>
    matchesFilter([r.name, r.algorithm, r.replace_with]),
  ),
)

const filteredTags = computed(() =>
  (policy.value?.column_tags || []).filter(t =>
    matchesFilter([t.column, t.mask_rule, t.label, joinList(t.tables), joinList(t.subjects)]),
  ),
)

const filteredHighRisk = computed(() =>
  (policy.value?.high_risk_rules || []).filter(r =>
    matchesFilter([r.name, r.kind, r.ticket_type, r.message, joinList(r.actions), joinList(r.tables)]),
  ),
)

const filteredTime = computed(() =>
  (policy.value?.time_rules || []).filter(r =>
    matchesFilter([r.name, r.effect, r.timezone, r.start, r.end, joinList(r.days), joinList(r.actions)]),
  ),
)

async function load() {
  setMessage('Loading security policies…')
  try {
    policy.value = await api.securityPolicies(apiBase.value)
    const p = policy.value
    const bits = [
      p.enabled ? 'enabled' : 'disabled',
      `${p.rule_count} rules`,
      `${(p.mask_rules || []).length} masks`,
      `${(p.column_tags || []).length} tags`,
      `${(p.high_risk_rules || []).length} high-risk`,
      `${(p.time_rules || []).length} time`,
    ]
    setMessage(bits.join(' · '), 'ok')
  }
  catch (e: any) {
    policy.value = null
    setMessage(e?.data?.message || e?.message || String(e), 'error')
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
          Security policies
        </h2>
        <div
          class="meta"
          :class="{ ok: messageKind === 'ok', err: messageKind === 'error' }"
        >
          {{ message }}
        </div>
      </div>
      <div class="row">
        <input
          v-model="filter"
          class="input"
          placeholder="Filter rules / masks / tags…"
          aria-label="Filter policies"
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

    <p class="hint">
      UI04 read-only view of <code class="mono">GET /admin/security-policies</code>.
      Edits stay in gateway config / Local PDP file / Cedar — this page never mutates policy.
    </p>

    <div
      v-if="policy"
      class="card"
    >
      <h3>Summary</h3>
      <dl class="kv">
        <div>
          <dt>Enabled</dt>
          <dd>
            <span
              class="badge"
              :class="policy.enabled ? 'on' : 'off'"
            >{{ policy.enabled ? 'on' : 'off' }}</span>
          </dd>
        </div>
        <div>
          <dt>fail_closed</dt>
          <dd class="mono">
            {{ policy.fail_closed }}
          </dd>
        </div>
        <div>
          <dt>star_policy</dt>
          <dd class="mono">
            {{ policy.star_policy }}
          </dd>
        </div>
        <div>
          <dt>default_audit_level</dt>
          <dd class="mono">
            {{ policy.default_audit_level }}
            <template v-if="policy.sql_text_max_chars != null">
              · sql_text_max_chars={{ policy.sql_text_max_chars }}
            </template>
          </dd>
        </div>
        <div>
          <dt>PDP backend</dt>
          <dd class="mono">
            {{ policy.pdp_backend }}
          </dd>
        </div>
        <div v-if="policy.pdp_policy_dir">
          <dt>policy_dir</dt>
          <dd class="mono">
            {{ policy.pdp_policy_dir }}
          </dd>
        </div>
        <div v-if="policy.pdp">
          <dt>pdp (F31)</dt>
          <dd class="mono">
            backend={{ policy.pdp.backend }}
            · remote_configured={{ policy.pdp.remote_configured }}
            · timeout_ms={{ policy.pdp.remote_timeout_ms }}
            · fail_closed={{ policy.pdp.remote_fail_closed }}
            · token={{ policy.pdp.remote_token_configured ? 'yes' : 'no' }}
          </dd>
        </div>
        <div v-if="policy.streaming">
          <dt>streaming.window_rows</dt>
          <dd class="mono">
            {{ policy.streaming.window_rows }}
          </dd>
        </div>
        <div v-if="policy.streaming">
          <dt>streaming.passthrough</dt>
          <dd class="mono">
            {{ policy.streaming.passthrough }}
          </dd>
        </div>
        <div v-if="policy.streaming?.max_rows != null">
          <dt>streaming.max_rows</dt>
          <dd class="mono">
            {{ policy.streaming.max_rows }}
          </dd>
        </div>
        <div v-if="policy.audit_sample">
          <dt>audit.sample</dt>
          <dd class="mono">
            {{ policy.audit_sample.sample_enabled ? 'on' : 'off' }}
            · max_rows={{ policy.audit_sample.sample_max_rows }}
            · max_bytes={{ policy.audit_sample.sample_max_bytes }}
            · inline={{ policy.audit_sample.sample_inline }}
            · prefix={{ policy.audit_sample.sample_prefix || 'samples' }}
            · needs L2
          </dd>
        </div>
        <div v-if="policy.audit_queue">
          <dt>audit.queue (B07)</dt>
          <dd class="mono">
            capacity={{ policy.audit_queue.queue_capacity }}
            · priority_capacity={{ policy.audit_queue.priority_queue_capacity }}
            · overflow={{ policy.audit_queue.overflow }}
            · sinks={{ (policy.audit_queue.sinks || []).join(',') || '—' }}
          </dd>
        </div>
        <div v-if="policy.state">
          <dt>state (H05)</dt>
          <dd class="mono">
            backend={{ policy.state.backend }}
            · ticket_enc={{ policy.state.ticket_encrypt_configured ? 'yes' : 'no' }}
            · vault_enc={{ policy.state.vault_encrypt_configured ? 'yes' : 'no' }}
            · poll_ms={{ policy.state.policy_poll_ms }}
          </dd>
        </div>
        <div v-if="policy.state && policy.state.backend === 'file'">
          <dt>state.paths</dt>
          <dd class="mono small">
            ticket={{ policy.state.ticket_path || '—' }}
            · vault={{ policy.state.vault_path || '—' }}
            · policy={{ policy.state.policy_path || '—' }}
          </dd>
        </div>
        <div v-if="policy.watermark">
          <dt>watermark</dt>
          <dd class="mono">
            {{ policy.watermark.enabled ? 'on' : 'off' }}
            · {{ policy.watermark.mode }}
            · col={{ policy.watermark.column }}
            · static_token={{ policy.watermark.has_static_token }}
          </dd>
        </div>
      </dl>
    </div>

    <div class="card">
      <h3>ACL rules ({{ filteredRules.length }})</h3>
      <div
        v-if="filteredRules.length"
        class="table-wrap"
      >
        <table class="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Effect</th>
              <th>Actions</th>
              <th>Tables</th>
              <th>Columns</th>
              <th>Subjects</th>
              <th>Row filter</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in filteredRules"
              :key="r.name"
            >
              <td class="mono">
                {{ r.name }}
              </td>
              <td>
                <span
                  class="badge"
                  :class="r.effect === 'allow' ? 'on' : 'off'"
                >{{ r.effect }}</span>
              </td>
              <td class="mono">
                {{ joinList(r.actions) }}
              </td>
              <td class="mono">
                {{ joinList(r.tables) }}
              </td>
              <td class="mono">
                {{ joinList(r.columns) }}
              </td>
              <td class="mono">
                {{ joinList(r.subjects) }}
              </td>
              <td class="mono">
                {{ r.row_filter || '—' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div
        v-else
        class="empty"
      >
        No ACL rules{{ filter ? ' match filter' : '' }}.
      </div>
    </div>

    <div class="card">
      <h3>Mask rules ({{ filteredMasks.length }})</h3>
      <div
        v-if="filteredMasks.length"
        class="table-wrap"
      >
        <table class="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Algorithm</th>
              <th>replace_with</th>
              <th>prefix</th>
              <th>suffix</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="m in filteredMasks"
              :key="m.name"
            >
              <td class="mono">
                {{ m.name }}
              </td>
              <td class="mono">
                {{ m.algorithm }}
              </td>
              <td class="mono">
                {{ m.replace_with || '—' }}
              </td>
              <td class="mono">
                {{ m.prefix_len }}
              </td>
              <td class="mono">
                {{ m.suffix_len }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div
        v-else
        class="empty"
      >
        No mask rules{{ filter ? ' match filter' : '' }}.
      </div>
    </div>

    <div class="card">
      <h3>Column tags ({{ filteredTags.length }})</h3>
      <div
        v-if="filteredTags.length"
        class="table-wrap"
      >
        <table class="tbl">
          <thead>
            <tr>
              <th>Column</th>
              <th>Mask rule</th>
              <th>Label</th>
              <th>Tables</th>
              <th>Subjects</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(t, i) in filteredTags"
              :key="`${t.column}-${t.mask_rule}-${i}`"
            >
              <td class="mono">
                {{ t.column }}
              </td>
              <td class="mono">
                {{ t.mask_rule }}
              </td>
              <td class="mono">
                {{ t.label || '—' }}
              </td>
              <td class="mono">
                {{ joinList(t.tables) }}
              </td>
              <td class="mono">
                {{ joinList(t.subjects) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div
        v-else
        class="empty"
      >
        No column tags{{ filter ? ' match filter' : '' }}.
      </div>
    </div>

    <div class="card">
      <h3>High-risk rules ({{ filteredHighRisk.length }})</h3>
      <div
        v-if="filteredHighRisk.length"
        class="table-wrap"
      >
        <table class="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>Ticket</th>
              <th>Actions</th>
              <th>Tables</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in filteredHighRisk"
              :key="r.name"
            >
              <td class="mono">
                {{ r.name }}
              </td>
              <td class="mono">
                {{ r.kind }}
              </td>
              <td class="mono">
                {{ r.ticket_type }}
              </td>
              <td class="mono">
                {{ joinList(r.actions) }}
              </td>
              <td class="mono">
                {{ joinList(r.tables) }}
              </td>
              <td>{{ r.message || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div
        v-else
        class="empty"
      >
        No high-risk rules{{ filter ? ' match filter' : '' }}.
      </div>
    </div>

    <div class="card">
      <h3>Time rules ({{ filteredTime.length }})</h3>
      <div
        v-if="filteredTime.length"
        class="table-wrap"
      >
        <table class="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Effect</th>
              <th>Window</th>
              <th>Outside</th>
              <th>Days</th>
              <th>TZ</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in filteredTime"
              :key="r.name"
            >
              <td class="mono">
                {{ r.name }}
              </td>
              <td class="mono">
                {{ r.effect }}
              </td>
              <td class="mono">
                {{ r.start }}–{{ r.end }}
              </td>
              <td class="mono">
                {{ r.outside }}
              </td>
              <td class="mono">
                {{ joinList(r.days) }}
              </td>
              <td class="mono">
                {{ r.timezone }}
              </td>
              <td class="mono">
                {{ joinList(r.actions) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div
        v-else
        class="empty"
      >
        No time rules{{ filter ? ' match filter' : '' }}.
      </div>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.hint { color: #57606a; font-size: .88rem; margin: 0 0 .75rem; }
.input {
  min-width: 14rem;
  padding: .4rem .55rem;
  border: 1px solid #d0d7de;
  border-radius: 6px;
  font-size: .9rem;
}
.meta.ok { color: #1a7f37; }
.meta.err { color: #cf222e; }
.card {
  background: #fff;
  border: 1px solid #e6ebf0;
  border-radius: 10px;
  padding: .85rem;
  margin-bottom: .75rem;
}
.card h3 { margin: 0 0 .55rem; font-size: 1rem; }
.kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: .55rem 1rem;
  margin: 0;
}
.kv > div { display: flex; flex-direction: column; gap: .12rem; }
.kv dt { font-size: .8rem; color: #57606a; }
.kv dd { margin: 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
.badge {
  display: inline-block;
  padding: .1rem .4rem;
  border-radius: 999px;
  font-size: .75rem;
  font-weight: 600;
  text-transform: lowercase;
}
.badge.on { background: #dafbe1; color: #1a7f37; }
.badge.off { background: #ffebe9; color: #cf222e; }
.table-wrap { overflow: auto; }
.tbl {
  width: 100%;
  border-collapse: collapse;
  font-size: .85rem;
}
.tbl th, .tbl td {
  text-align: left;
  padding: .4rem .45rem;
  border-bottom: 1px solid #eef1f4;
  vertical-align: top;
}
.tbl th {
  color: #57606a;
  font-weight: 600;
  white-space: nowrap;
}
.empty { color: #888; font-size: .9rem; }
@media (max-width: 720px) {
  .kv { grid-template-columns: 1fr; }
  .input { min-width: 0; width: 100%; }
}
.small { font-size: .85em; word-break: break-all; }
</style>
