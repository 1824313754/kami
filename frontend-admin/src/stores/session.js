import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { fetchJobs, fetchSession, login, logout } from '../api/admin'

export const useSessionStore = defineStore('session', () => {
  const session = ref(null)
  const jobs = ref([])
  const initialized = ref(false)
  const loading = ref(false)

  const isAuthenticated = computed(() => Boolean(session.value?.authenticated))
  const csrfToken = computed(() => session.value?.csrf_token || '')

  function applySession(nextSession) {
    session.value = nextSession
    window.__PYFAKA_CSRF_TOKEN__ = nextSession?.csrf_token || ''
  }

  async function bootstrap() {
    if (loading.value) {
      return
    }
    loading.value = true
    try {
      const data = await fetchSession()
      applySession(data.session)
      jobs.value = data.jobs || []
    } finally {
      initialized.value = true
      loading.value = false
    }
  }

  async function signIn(payload) {
    const data = await login(payload)
    applySession(data.session)
    jobs.value = data.jobs || []
    initialized.value = true
    return data
  }

  async function signOut() {
    await logout()
    applySession(null)
    jobs.value = []
    initialized.value = true
  }

  async function refreshJobs(params = null) {
    if (!session.value?.authenticated) return
    const scope = session.value?.pool?.scope || {}
    const query = params ? { ...scope, ...params } : scope
    const data = await fetchJobs(query)
    jobs.value = data.items || []
  }

  function patchPool(nextPool) {
    if (!session.value) return
    session.value = {
      ...session.value,
      pool: nextPool,
    }
  }

  return {
    session,
    jobs,
    initialized,
    loading,
    isAuthenticated,
    csrfToken,
    bootstrap,
    signIn,
    signOut,
    refreshJobs,
    applySession,
    patchPool,
  }
})
