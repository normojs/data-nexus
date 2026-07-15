<script setup lang="ts">
definePageMeta({ layout: false })
useHead({ title: 'Login · Data Nexus Admin' })

const route = useRoute()
const {
  authRequired,
  login,
  hydrateFromStorage,
  authenticated,
  passwordEnabled,
  oidcEnabled,
} = useAdminAuth()
const oidc = useOidc()

const password = ref('')
const error = ref('')
const busy = ref(false)

onMounted(() => {
  hydrateFromStorage()
  if (!authRequired.value || authenticated.value) {
    navigateTo(String(route.query.next || '/'))
  }
})

function submit() {
  error.value = ''
  if (!passwordEnabled.value) {
    error.value = 'Password auth is disabled; use SSO'
    return
  }
  if (login(password.value)) {
    navigateTo(String(route.query.next || '/'))
    return
  }
  error.value = 'Invalid password'
}

async function sso() {
  error.value = ''
  busy.value = true
  try {
    await oidc.startLogin(String(route.query.next || '/'))
  }
  catch (err: any) {
    error.value = err?.message || String(err)
    busy.value = false
  }
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
        Sign in to manage the gateway.
      </p>

      <template v-if="passwordEnabled">
        <label class="field-label">
          Password
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            autofocus
          >
        </label>
        <button
          type="submit"
          class="btn primary"
          style="width: 100%; margin-top: 12px"
        >
          Sign in with password
        </button>
      </template>

      <div
        v-if="passwordEnabled && oidcEnabled"
        class="divider"
      >
        or
      </div>

      <button
        v-if="oidcEnabled"
        type="button"
        class="btn"
        style="width: 100%"
        :disabled="busy"
        @click="sso"
      >
        {{ busy ? 'Redirecting…' : 'Sign in with SSO (OIDC)' }}
      </button>

      <p
        v-if="error"
        class="status-line error"
      >
        {{ error }}
      </p>

      <p class="meta">
        Password: <code class="mono">NUXT_PUBLIC_ADMIN_PASSWORD</code>.
        SSO: <code class="mono">NUXT_PUBLIC_OIDC_ISSUER</code> +
        <code class="mono">NUXT_PUBLIC_OIDC_CLIENT_ID</code> (PKCE public client).
        Leave both empty to disable the login gate.
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
.divider {
  text-align: center;
  color: var(--muted);
  font-size: 0.8rem;
  margin: 14px 0;
}
</style>
