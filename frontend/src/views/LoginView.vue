<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowRight, Eye, EyeOff, LockKeyhole, ShieldCheck, UserRound } from 'lucide-vue-next'
import { useAuth } from '@/auth'
import { ApiError } from '@/api/client'

const route = useRoute()
const router = useRouter()
const auth = useAuth()
const username = ref('')
const password = ref('')
const showPassword = ref(false)
const pending = ref(false)
const errorMessage = ref('')

async function submit() {
  if (!username.value.trim() || !password.value) {
    errorMessage.value = '请输入管理员账号和密码'
    return
  }
  pending.value = true
  errorMessage.value = ''
  try {
    await auth.login(username.value.trim(), password.value)
    await router.replace(typeof route.query.redirect === 'string' ? route.query.redirect : '/')
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '登录失败，请检查服务是否可用'
  } finally {
    pending.value = false
  }
}
</script>

<template>
  <main class="login-page">
    <div class="login-grid-art" aria-hidden="true"><span /><span /><span /><span /><span /></div>
    <section class="login-brand-panel">
      <div class="brand-lockup large"><div class="brand-mark"><ShieldCheck :size="25" /></div><div class="brand-copy"><strong>NoCyber</strong><span>GUARD / CONTROL</span></div></div>
      <div class="login-intro">
        <p class="eyebrow">SECURITY OPERATIONS</p>
        <h1>让每一次请求<br /><em>先过安全门。</em></h1>
        <p>集中管理提示词审核、风险规则与运行状态，让安全策略清晰、可靠、可追溯。</p>
        <div class="login-capabilities" aria-label="核心能力">
          <div><span>01</span><strong>实时预检</strong><small>请求进入上游前完成策略判断</small></div>
          <div><span>02</span><strong>智能复核</strong><small>多节点并行投票，持续沉淀规则</small></div>
          <div><span>03</span><strong>完整追踪</strong><small>决策、延迟与证据统一留痕</small></div>
        </div>
      </div>
      <div class="login-footnote"><span class="status-dot" /> Guard 服务已准备就绪</div>
    </section>
    <section class="login-form-panel">
      <div class="login-form-card">
        <div class="mobile-login-logo"><div class="brand-mark"><ShieldCheck :size="21" /></div><strong>NoCyber Guard</strong></div>
        <div class="login-card-heading"><p class="eyebrow">ADMIN CONSOLE</p><span class="login-version">SECURE ACCESS</span></div>
        <h2>欢迎回来</h2><p class="muted">登录 NoCyber Guard 管理控制台</p>
        <form @submit.prevent="submit">
          <label class="field-label" for="username">管理员账号</label>
          <div class="input-with-icon"><UserRound :size="17" /><input id="username" v-model="username" autocomplete="username" placeholder="输入账号" /></div>
          <label class="field-label" for="password">密码</label>
          <div class="input-with-icon"><LockKeyhole :size="17" /><input id="password" v-model="password" :type="showPassword ? 'text' : 'password'" autocomplete="current-password" placeholder="输入密码" /><button type="button" class="input-action" :aria-label="showPassword ? '隐藏密码' : '显示密码'" @click="showPassword = !showPassword"><EyeOff v-if="showPassword" :size="17" /><Eye v-else :size="17" /></button></div>
          <p v-if="errorMessage" class="form-error" role="alert">{{ errorMessage }}</p>
          <button class="primary-button login-submit" type="submit" :disabled="pending"><span>{{ pending ? '正在验证…' : '登录控制台' }}</span><ArrowRight :size="17" /></button>
        </form>
        <p class="login-security"><LockKeyhole :size="14" /> 仅限授权管理员访问</p>
      </div>
    </section>
  </main>
</template>
