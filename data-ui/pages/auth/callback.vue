<script setup lang="ts">
definePageMeta({ layout: false })
useHead({ title: 'SSO callback · Data Nexus Admin' })

const route = useRoute()
const oidc = useOidc()
const { markOidcAuthenticated } = useAdminAuth()
const error = ref('')
const status = ref('Completing SSO sign-in…')

onMounted(async () => {
  try {
    const next = await oidc.handleCallback(route.query as Record<string, string>)
    markOidcAuthenticated()
    status.value = 'Signed in. Redirecting…'
    await navigateTo(next || '/')
  }
  catch (err: any) {
    error.value = err?.message || String(err)
    status.value = 'SSO failed'
  }
})
</script>

<template>
  <div class="login-page">
    <div class="login-card">
      <h1>SSO</h1>
      <p class="meta">
        {{ status }}
      </p>
      <p
        v-if="error"
        class="status-line error"
      >
        {{ error }}
      </p>
      <NuxtLink
        v-if="error"
        class="btn primary"
        to="/login"
        style="display: inline-block; margin-top: 12px"
      >
        Back to login
      </NuxtLink>
    </div>
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
  width: min(420px, 100%);
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
}
.login-card h1 {
  margin: 0 0 8px;
  font-size: 1.2rem;
}
</style>
