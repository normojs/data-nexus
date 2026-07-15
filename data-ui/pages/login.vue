<script setup lang="ts">
definePageMeta({ layout: false })
useHead({ title: 'Login · Data Nexus Admin' })

const route = useRoute()
const { authRequired, login, hydrateFromStorage, authenticated } = useAdminAuth()
const password = ref('')
const error = ref('')

onMounted(() => {
  hydrateFromStorage()
  if (!authRequired.value || authenticated.value) {
    navigateTo(String(route.query.next || '/'))
  }
})

function submit() {
  error.value = ''
  if (login(password.value)) {
    navigateTo(String(route.query.next || '/'))
    return
  }
  error.value = 'Invalid password'
}
</script>

<template>
  <div class="login-page">
    <form
      class="login-card"
      @submit.prevent="submit"
    >
      <h1>Data Nexus Admin</h1>
      <p class="meta">
        Enter the admin password to continue.
      </p>
      <label class="field-label">
        Password
        <input
          v-model="password"
          type="password"
          autocomplete="current-password"
          autofocus
        >
      </label>
      <p
        v-if="error"
        class="status-line error"
      >
        {{ error }}
      </p>
      <button
        type="submit"
        class="btn primary"
        style="width: 100%; margin-top: 12px"
      >
        Sign in
      </button>
      <p class="meta">
        Set <code class="mono">NUXT_PUBLIC_ADMIN_PASSWORD</code> to enable auth.
        Leave empty to disable the login gate.
      </p>
    </form>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
}
.login-card {
  width: min(400px, 100%);
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
}
.login-card h1 {
  margin: 0 0 8px;
  font-size: 1.2rem;
}
.field-label {
  display: grid;
  gap: 6px;
  font-size: 0.85rem;
  color: var(--muted);
  margin-top: 16px;
}
.field-label input {
  background: #0c1118;
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 8px;
  padding: 10px 12px;
  font-size: 0.95rem;
}
</style>
