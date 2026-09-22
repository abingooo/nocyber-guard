<script setup lang="ts">
import { ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { Activity, Fingerprint, Gauge, LogOut, Menu, Settings, ShieldAlert, ShieldCheck, X } from 'lucide-vue-next'
import { useAuth } from '@/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuth()
const mobileOpen = ref(false)

const navigation = [
  { name: 'overview', label: '总览', icon: Gauge, to: '/' },
  { name: 'events', label: '审核事件', icon: Activity, to: '/events' },
  { name: 'trusted', label: '可信库', icon: ShieldCheck, to: '/trusted' },
  { name: 'risks', label: '风险库', icon: ShieldAlert, to: '/risks' },
  { name: 'clients', label: '客户端规则', icon: Fingerprint, to: '/clients' },
  { name: 'settings', label: '系统设置', icon: Settings, to: '/settings' },
]

async function signOut() {
  await auth.logout()
  await router.replace({ name: 'login' })
}

function navigate() {
  mobileOpen.value = false
}
</script>

<template>
  <div class="app-frame top-navigation-layout">
    <header class="app-header">
      <div class="app-header-inner">
        <RouterLink to="/" class="header-brand" aria-label="NoCyber Guard 总览" @click="navigate">
          <div class="brand-mark"><ShieldCheck :size="20" stroke-width="2.5" /></div>
          <div class="brand-copy"><strong>NoCyber</strong><span>GUARD / CONTROL</span></div>
        </RouterLink>

        <nav class="top-navigation" :class="{ 'mobile-open': mobileOpen }" aria-label="主导航">
          <RouterLink
            v-for="item in navigation"
            :key="item.name"
            :to="item.to"
            class="top-nav-item"
            :class="{ active: route.name === item.name }"
            @click="navigate"
          >
            <component :is="item.icon" :size="17" />
            <span>{{ item.label }}</span>
          </RouterLink>
        </nav>

        <div class="header-actions">
          <span class="live-indicator"><i />在线</span>
          <div class="header-user">
            <span class="avatar">{{ auth.username.value.slice(0, 1).toUpperCase() }}</span>
            <span class="header-username">{{ auth.username }}</span>
          </div>
          <button class="icon-button header-logout" title="退出登录" aria-label="退出登录" @click="signOut"><LogOut :size="17" /></button>
          <button class="icon-button header-menu" :aria-label="mobileOpen ? '关闭菜单' : '打开菜单'" @click="mobileOpen = !mobileOpen">
            <X v-if="mobileOpen" :size="20" /><Menu v-else :size="20" />
          </button>
        </div>
      </div>
    </header>

    <main class="main-panel">
      <div class="content-wrap"><RouterView /></div>
    </main>
  </div>
</template>
