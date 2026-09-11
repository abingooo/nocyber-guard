import { computed, ref } from 'vue'
import { api, ApiError } from '@/api/client'

const authenticated = ref(sessionStorage.getItem('nocyber.authenticated') === '1')
const username = ref(sessionStorage.getItem('nocyber.username') || '管理员')
let verification: Promise<boolean> | null = null

function setSession(value: boolean, user?: string) {
  authenticated.value = value
  if (value) {
    username.value = user || username.value
    sessionStorage.setItem('nocyber.authenticated', '1')
    sessionStorage.setItem('nocyber.username', username.value)
  } else {
    sessionStorage.removeItem('nocyber.authenticated')
    sessionStorage.removeItem('nocyber.username')
  }
}

export function useAuth() {
  async function login(user: string, password: string) {
    const result = await api.login(user, password)
    setSession(true, result?.username || user)
  }

  async function logout() {
    try {
      await api.logout()
    } finally {
      setSession(false)
    }
  }

  async function verify() {
    if (!authenticated.value) return false
    if (!verification) {
      verification = api
        .getOverview()
        .then(() => true)
        .catch((error: unknown) => {
          if (error instanceof ApiError && error.status === 401) setSession(false)
          return authenticated.value
        })
        .finally(() => {
          verification = null
        })
    }
    return verification
  }

  return {
    authenticated: computed(() => authenticated.value),
    username: computed(() => username.value),
    login,
    logout,
    verify,
  }
}
