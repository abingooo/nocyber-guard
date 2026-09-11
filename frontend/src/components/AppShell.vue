<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import {
  Activity,
  ChevronRight,
  CircleHelp,
  Fingerprint,
  Gauge,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-vue-next'
import { useAuth } from '@/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuth()
const collapsed = ref(false)
const mobileOpen = ref(false)

const navigation = [
  { name: 'overview', label: '总览', hint: '运行状态与趋势', icon: Gauge, to: '/' },
  { name: 'events', label: '审核事件', hint: '检索与证据', icon: Activity, to: '/events' },
  { name: 'trusted', label: '可信库', hint: '快速放行规则', icon: ShieldCheck, to: '/trusted' },
  { name: 'risks', label: '风险库', hint: '阻断规则', icon: ShieldAlert, to: '/risks' },
  { name: 'clients', label: '客户端规则', hint: '识别与匹配', icon: Fingerprint, to: '/clients' },
  { name: 'settings', label: '系统设置', hint: '代理与审核节点', icon: Settings, to: '/settings' },
]

const currentLabel = computed(() => navigation.find((item) => item.name === route.name)?.label || '总览')

async function signOut() {
  await auth.logout()
  await router.replace({ name: 'login' })
}

function navigate() {
  mobileOpen.value = false
}
</script>

<template>
  <div class="app-frame">
    <div v-if="mobileOpen" class="mobile-scrim" @click="mobileOpen = false" />
    <aside class="sidebar" :class="{ collapsed, 'mobile-open': mobileOpen }">
      <div class="brand-lockup">
        <div class="brand-mark"><ShieldCheck :size="21" stroke-width="2.5" /></div>
        <div v-if="!collapsed" class="brand-copy">
          <strong>NoCyber</strong>
          <span>GUARD / CONTROL</span>
        </div>
        <button v-if="mobileOpen" class="icon-button mobile-close" aria-label="关闭菜单" @click="mobileOpen = false">
          <X :size="18" />
        </button>
      </div>

      <div v-if="!collapsed" class="sidebar-kicker">安全运营台</div>
      <nav class="main-nav" aria-label="主导航">
        <RouterLink
          v-for="item in navigation"
          :key="item.name"
          :to="item.to"
          class="nav-item"
          :class="{ active: route.name === item.name }"
          :title="collapsed ? item.label : undefined"
          @click="navigate"
        >
          <component :is="item.icon" :size="19" />
          <span v-if="!collapsed" class="nav-label">
            <strong>{{ item.label }}</strong>
            <small>{{ item.hint }}</small>
          </span>
          <ChevronRight v-if="!collapsed && route.name === item.name" class="nav-arrow" :size="15" />
        </RouterLink>
      </nav>

      <div class="sidebar-bottom">
        <RouterLink to="/settings" class="support-link" @click="navigate">
          <CircleHelp :size="18" />
          <span v-if="!collapsed">运行帮助</span>
        </RouterLink>
        <div class="user-chip">
          <div class="avatar">{{ auth.username.value.slice(0, 1).toUpperCase() }}</div>
          <div v-if="!collapsed" class="user-meta">
            <strong>{{ auth.username }}</strong>
            <span>管理员</span>
          </div>
          <button class="icon-button logout-button" title="退出登录" aria-label="退出登录" @click="signOut">
            <LogOut :size="16" />
          </button>
        </div>
      </div>

      <button class="collapse-button" :aria-label="collapsed ? '展开菜单' : '收起菜单'" @click="collapsed = !collapsed">
        <PanelLeftOpen v-if="collapsed" :size="17" />
        <PanelLeftClose v-else :size="17" />
        <span v-if="!collapsed">收起菜单</span>
      </button>
    </aside>

    <main class="main-panel">
      <header class="topbar">
        <button class="icon-button mobile-menu" aria-label="打开菜单" @click="mobileOpen = true"><Menu :size="21" /></button>
        <div class="breadcrumb"><span>安全审计</span><ChevronRight :size="14" /><strong>{{ currentLabel }}</strong></div>
        <div class="topbar-actions">
          <span class="live-indicator"><i /> 在线</span>
          <span class="topbar-date">{{ new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' }) }}</span>
        </div>
      </header>
      <div class="content-wrap"><RouterView /></div>
    </main>
  </div>
</template>
