<template>
  <div v-if="booting" class="boot"><span class="boot-dot" />正在连接 EDR 后台…</div>
  <Login v-else-if="!user || user.must_change" :user="user" @done="onLogin" @logout="logout" />
  <App v-else :user="user" @logout="logout" @user-updated="onLogin" />
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import App from './App.vue'
import Login from './Login.vue'
import { AUTH_EVENT, edrLogout, edrSession } from './api.js'

const user = ref(null)
const booting = ref(true)

function onLogin(u) {
  user.value = u || null
}

async function logout() {
  try { await edrLogout() } catch { /* ignore */ }
  user.value = null
}

function onUnauthorized() {
  user.value = null
}

onMounted(async () => {
  window.addEventListener(AUTH_EVENT, onUnauthorized)
  try {
    const r = await edrSession()
    user.value = r.user
  } catch {
    user.value = null
  } finally {
    booting.value = false
  }
})

onBeforeUnmount(() => window.removeEventListener(AUTH_EVENT, onUnauthorized))
</script>

<style scoped>
.boot {
  height: 100%; display: flex; align-items: center; justify-content: center; gap: 10px;
  color: var(--muted); font-size: 14px;
}
.boot-dot {
  width: 10px; height: 10px; border-radius: 50%; background: var(--accent);
  animation: boot-pulse 1s ease-in-out infinite;
}
@keyframes boot-pulse { 50% { opacity: .3; transform: scale(.7); } }
</style>
