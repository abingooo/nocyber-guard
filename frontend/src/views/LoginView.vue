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
      <div class="login-intro"><p class="eyebrow">SECURITY OPERATIONS</p><h1>让每一次请求<br /><em>先过安全门。</em></h1><p>集中管理提示词审核、风险规则与运行状态。</p></div>
      <div class="login-footnote"><span class="status-dot" /> Guard 服务已准备就绪</div>
    </section>
    <section class="login-form-panel">
      <div class="login-form-card">
        <div class="mobile-login-logo"><div class="brand-mark"><ShieldCheck :size="21" /></div><strong>NoCyber Guard</strong></div>
        <p class="eyebrow">ADMIN CONSOLE</p><h2>欢迎回来</h2><p class="muted">登录管理后台以继续操作</p>
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
