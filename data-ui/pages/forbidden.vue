<script setup lang="ts">
definePageMeta({ layout: 'admin' })
useHead({ title: 'Access denied · Data Nexus Admin' })

const route = useRoute()
const { logout, authRequired } = useAdminAuth()

const reason = computed(() => String(route.query.reason || 'forbidden'))
const message = computed(() => {
  const m = String(route.query.message || '').trim()
  if (m) return m
  return 'Your account is signed in, but it does not have permission for this Admin API action.'
})
const path = computed(() => String(route.query.path || '').trim())

const tips = computed(() => {
  const items = [
    'Confirm you signed in with an operator or admin role, not a read-only viewer.',
    'Ask an administrator to grant the missing Admin permission (for example policy:write or config:reload).',
  ]
  if (reason.value.includes('ticket') || path.value.includes('ticket')) {
    items.push('Ticket issue/approve requires PolicyWrite; listing tickets only needs RuntimeRead.')
  }
  if (path.value.includes('reload')) {
    items.push('Config reload requires the config:reload permission (admin role).')
  }
  return items
})

function goHome() {
  navigateTo('/')
}

function goLogin() {
  if (authRequired.value) {
    logout()
  }
  navigateTo({ path: '/login', query: { next: '/', reason: 'reauth' } })
}
</script>

<template>
  <div class="page forbidden-page">
    <div class="forbidden-card">
      <div class="badge">
        403
      </div>
      <h1 class="page-title">
        Access denied
      </h1>
      <p class="meta lead">
        {{ message }}
      </p>

      <dl class="detail-list">
        <div>
          <dt>Reason code</dt>
          <dd class="mono">
            {{ reason }}
          </dd>
        </div>
        <div v-if="path">
          <dt>API path</dt>
          <dd class="mono">
            {{ path }}
          </dd>
        </div>
      </dl>

      <div class="tips">
        <h2>What you can do</h2>
        <ul>
          <li
            v-for="(tip, i) in tips"
            :key="i"
          >
            {{ tip }}
          </li>
        </ul>
      </div>

      <div class="actions">
        <button
          type="button"
          class="btn primary"
          @click="goHome"
        >
          Back to overview
        </button>
        <button
          type="button"
          class="btn"
          @click="goLogin"
        >
          Sign in with another account
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.forbidden-page {
  display: grid;
  place-items: center;
  min-height: 50vh;
}
.forbidden-card {
  width: min(560px, 100%);
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 28px 24px;
}
.badge {
  display: inline-block;
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--err);
  background: rgba(240, 113, 120, 0.12);
  border: 1px solid rgba(240, 113, 120, 0.35);
  border-radius: 999px;
  padding: 2px 10px;
  margin-bottom: 12px;
}
.lead {
  margin: 8px 0 16px;
  line-height: 1.5;
  color: var(--text);
}
.detail-list {
  display: grid;
  gap: 10px;
  margin: 0 0 18px;
}
.detail-list dt {
  font-size: 0.75rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.detail-list dd {
  margin: 2px 0 0;
  word-break: break-all;
}
.tips h2 {
  margin: 0 0 8px;
  font-size: 0.9rem;
}
.tips ul {
  margin: 0;
  padding-left: 1.2rem;
  color: var(--muted);
  font-size: 0.9rem;
  line-height: 1.5;
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 20px;
}
.mono {
  font-family: var(--mono);
  font-size: 0.85rem;
}
</style>
