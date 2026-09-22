<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import {
  AlertTriangle,
  Check,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  Link2,
  LoaderCircle,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  ShieldCheck,
  TestTube2,
  Zap,
} from 'lucide-vue-next'
import { api, ApiError } from '@/api/client'
import type { AIEndpoint, AINode, GuardConfig, SystemUpdateStatus } from '@/types'
import { useToast } from '@/composables/toast'

const defaultConfig: GuardConfig = {
  version: 0,
  enabled: true,
  mode: 'permissive',
  upstream_url: '',
  protected_paths: ['/v1/responses', '/responses', '/backend-api/codex/responses'],
  request_timeout_ms: 15000,
  max_body_bytes: 4 * 1024 * 1024,
  event_retention_days: 30,
}
const defaultEndpoint: AIEndpoint = {
  base_url: '',
  model: '',
  api_key: '',
  has_api_key: false,
  timeout_ms: 15000,
  max_concurrency: 16,
}
const defaultAsyncNodes: AINode[] = (['async_1', 'async_2', 'async_3'] as const).map((slot, index) => ({
  slot,
  name: `异步节点 ${index + 1}`,
  base_url: '',
  model: '',
  api_key: '',
  has_api_key: false,
  timeout_ms: 15000,
  enabled: true,
}))

const config = ref<GuardConfig>(cloneConfig(defaultConfig))
const endpoint = ref<AIEndpoint>({ ...defaultEndpoint })
const savedConfig = ref<GuardConfig>(cloneConfig(defaultConfig))
const savedEndpoint = ref<AIEndpoint>({ ...defaultEndpoint })
const asyncNodes = ref<AINode[]>(cloneNodes(defaultAsyncNodes))
const savedAsyncNodes = ref<AINode[]>(cloneNodes(defaultAsyncNodes))
const configSnapshot = ref('')
const endpointSnapshot = ref('')
const asyncNodesSnapshot = ref('')
const loading = ref(true)
const savingConfig = ref(false)
const savingEndpoint = ref(false)
const savingAsyncNodes = ref(false)
const testing = ref(false)
const showKey = ref(false)
const error = ref('')
const testResult = ref<{ ok: boolean; message: string; latency?: number } | null>(null)
const asyncTestResult = ref<Record<string, { ok: boolean; message: string; latency?: number }>>({})
const updateStatus = ref<SystemUpdateStatus | null>(null)
const checkingUpdate = ref(false)
const startingUpdate = ref(false)
let updatePoll: number | undefined
const toast = useToast()

const configDirty = computed(() => configSnapshot.value !== serializeConfig(config.value))
const endpointDirty = computed(() => endpointSnapshot.value !== serializeEndpoint(endpoint.value))
const bodyLimitMB = computed({
  get: () => Math.round(config.value.max_body_bytes / 1024 / 1024),
  set: (value: number) => {
    config.value.max_body_bytes = Math.max(1, Number(value) || 1) * 1024 * 1024
  },
})

function cloneConfig(value: GuardConfig): GuardConfig {
  return {
    version: value.version,
    enabled: value.enabled,
    mode: value.mode,
    upstream_url: value.upstream_url,
    protected_paths: [...value.protected_paths],
    request_timeout_ms: value.request_timeout_ms,
    max_body_bytes: value.max_body_bytes,
    event_retention_days: value.event_retention_days,
  }
}

function cloneNodes(value: AINode[]): AINode[] {
  return value.map((node) => ({ ...node, api_key: node.api_key || '' }))
}

function serializeNodes(value: AINode[]) {
  return JSON.stringify(value.map((node) => ({ ...node, api_key: node.api_key ? '__changed__' : '' })))
}

function serializeConfig(value: GuardConfig) {
  return JSON.stringify(cloneConfig(value))
}

function serializeEndpoint(value: AIEndpoint) {
  return JSON.stringify({ ...value, api_key: value.api_key ? '__changed__' : '' })
}

function applyConfig(value: GuardConfig) {
  const normalized = cloneConfig({
    ...defaultConfig,
    ...value,
    mode: 'permissive',
    protected_paths: value.protected_paths?.length ? value.protected_paths : defaultConfig.protected_paths,
  })
  config.value = cloneConfig(normalized)
  savedConfig.value = cloneConfig(normalized)
  configSnapshot.value = serializeConfig(normalized)
}

function applyEndpoint(value?: AIEndpoint) {
  const normalized = {
    ...defaultEndpoint,
    ...(value || {}),
    timeout_ms: value?.timeout_ms || defaultEndpoint.timeout_ms,
    max_concurrency: value?.max_concurrency || defaultEndpoint.max_concurrency,
    api_key: '',
  }
  endpoint.value = { ...normalized }
  savedEndpoint.value = { ...normalized }
  endpointSnapshot.value = serializeEndpoint(normalized)
  showKey.value = false
}

function applyAsyncNodes(value?: AINode[]) {
  const bySlot = new Map((value || []).map((node) => [node.slot, node]))
  const normalized = cloneNodes(defaultAsyncNodes).map((fallback) => ({ ...fallback, ...(bySlot.get(fallback.slot) || {}), api_key: '' }))
  asyncNodes.value = cloneNodes(normalized)
  savedAsyncNodes.value = cloneNodes(normalized)
  asyncNodesSnapshot.value = serializeNodes(normalized)
}

async function load() {
  loading.value = true
  error.value = ''
  testResult.value = null
  try {
    const loaded = await api.getConfig()
    applyConfig(loaded)
    applyEndpoint(loaded.ai_endpoint)
    applyAsyncNodes(loaded.async_nodes)
  } catch (requestError) {
    error.value = requestError instanceof ApiError ? requestError.message : '无法加载系统配置'
  } finally {
    loading.value = false
  }
}

const asyncNodesDirty = computed(() => asyncNodesSnapshot.value !== serializeNodes(asyncNodes.value))
const isLatestVersion = computed(() => {
  const current = updateStatus.value?.current_version?.replace(/^v/, '')
  const latest = updateStatus.value?.latest_version?.replace(/^v/, '')
  return Boolean(current && latest && current === latest)
})

async function saveAsyncNodes() {
  if (asyncNodes.value.some((node) => !node.base_url.trim() || !node.model.trim())) {
    toast.show('请补全三个异步节点配置', { tone: 'error' })
    return
  }
  savingAsyncNodes.value = true
  try {
    const saved = await api.updateAINodes(cloneNodes(asyncNodes.value))
    applyAsyncNodes(saved.items)
    toast.show('异步投票节点已保存')
  } catch (requestError) {
    toast.show('异步节点保存失败', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
  } finally {
    savingAsyncNodes.value = false
  }
}

async function testAsyncNode(node: AINode) {
  asyncTestResult.value[node.slot] = { ok: false, message: '测试中…' }
  try {
    const result = await api.testAINode({ ...node, api_key: node.api_key || '' })
    asyncTestResult.value[node.slot] = { ok: result.ok, message: result.message || (result.ok ? '节点响应正常' : '节点测试未通过'), latency: result.latency_ms }
  } catch (requestError) {
    asyncTestResult.value[node.slot] = { ok: false, message: requestError instanceof ApiError ? requestError.message : '节点连接失败' }
  }
}

async function saveConfig() {
  if (!/^https?:\/\/[^\s]+$/i.test(config.value.upstream_url.trim())) {
    toast.show('请输入有效的 HTTP 或 HTTPS 上游服务地址', { tone: 'error' })
    return
  }
  savingConfig.value = true
  try {
    const next = cloneConfig(config.value)
    next.upstream_url = next.upstream_url.trim().replace(/\/$/, '')
    const saved = await api.updateConfig(next)
    applyConfig(saved)
    toast.show('Guard 配置已保存')
  } catch (requestError) {
    if (requestError instanceof ApiError && requestError.status === 409) {
      toast.show('Guard 配置已被其他管理员更新', { detail: '请重新加载后再保存。AI 节点未受影响。', tone: 'error' })
    } else {
      toast.show('Guard 配置保存失败', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
    }
  } finally {
    savingConfig.value = false
  }
}

async function saveEndpoint() {
  if (!endpoint.value.base_url.trim() || !endpoint.value.model.trim()) {
    toast.show('请补全审核节点配置', { tone: 'error' })
    return
  }
  savingEndpoint.value = true
  try {
    const saved = await api.updateAIEndpoint({
      ...endpoint.value,
      base_url: endpoint.value.base_url.trim(),
      model: endpoint.value.model.trim(),
    })
    applyEndpoint(saved)
    testResult.value = null
    toast.show('AI 节点已保存')
  } catch (requestError) {
    toast.show('AI 节点保存失败', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
  } finally {
    savingEndpoint.value = false
  }
}

async function testEndpoint() {
  if (!endpoint.value.base_url.trim() || !endpoint.value.model.trim()) {
    toast.show('请先填写节点地址和模型', { tone: 'error' })
    return
  }
  testing.value = true
  testResult.value = null
  try {
    const result = await api.testAIEndpoint(endpoint.value)
    testResult.value = {
      ok: result.ok,
      message: result.message || (result.ok ? '节点响应正常' : '节点测试未通过'),
      latency: result.latency_ms,
    }
  } catch (requestError) {
    testResult.value = { ok: false, message: requestError instanceof ApiError ? requestError.message : '节点连接失败' }
  } finally {
    testing.value = false
  }
}

function resetConfig() {
  config.value = cloneConfig(savedConfig.value)
}

function resetEndpoint() {
  endpoint.value = { ...savedEndpoint.value }
  testResult.value = null
  showKey.value = false
}

function resetAsyncNodes() {
  asyncNodes.value = cloneNodes(savedAsyncNodes.value)
  asyncTestResult.value = {}
}

function shortImage(value?: string) {
  if (!value) return '未知'
  const digest = value.match(/sha256:([a-f0-9]{64})$/)?.[1]
  return digest ? `sha256:${digest.slice(0, 12)}…${digest.slice(-8)}` : value
}

async function loadUpdateStatus(silent = false) {
  if (!silent) checkingUpdate.value = true
  try {
    updateStatus.value = await api.getSystemUpdate()
    if (updateStatus.value.state === 'running') scheduleUpdatePoll()
  } catch (requestError) {
    if (!silent) toast.show('无法读取更新状态', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
  } finally {
    checkingUpdate.value = false
  }
}

function scheduleUpdatePoll() {
  if (updatePoll) window.clearTimeout(updatePoll)
  updatePoll = window.setTimeout(async () => {
    await loadUpdateStatus(true)
    if (updateStatus.value?.state === 'running') scheduleUpdatePoll()
  }, 3000)
}

async function startUpdate() {
  const target = updateStatus.value?.latest_version
  if (!target || !window.confirm(`确认将 NoCyber Guard 更新到 ${target}？更新时管理页面会短暂断开。`)) return
  startingUpdate.value = true
  try {
    await api.startSystemUpdate(target)
    toast.show('更新任务已开始', { detail: '服务会自动做健康检查，失败时自动回滚。' })
    await loadUpdateStatus(true)
    scheduleUpdatePoll()
  } catch (requestError) {
    toast.show('无法开始更新', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
  } finally {
    startingUpdate.value = false
  }
}

async function rollbackSystem() {
  if (!window.confirm('确认回滚到上一个健康镜像？管理页面会短暂断开。')) return
  startingUpdate.value = true
  try {
    await api.rollbackSystem()
    toast.show('回滚任务已开始')
    await loadUpdateStatus(true)
    scheduleUpdatePoll()
  } catch (requestError) {
    toast.show('无法开始回滚', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
  } finally {
    startingUpdate.value = false
  }
}

onMounted(() => { void load(); void loadUpdateStatus() })
onUnmounted(() => { if (updatePoll) window.clearTimeout(updatePoll) })
</script>

<template>
  <section class="page-view settings-view">
    <div class="page-heading">
      <div>
        <p class="eyebrow">CONFIGURATION / RUNTIME</p>
        <h1>系统设置</h1>
        <p class="page-subtitle">分别管理 Guard 运行配置与 AI 审核节点。</p>
      </div>
    </div>

    <div v-if="error" class="error-banner" role="alert">
      <AlertTriangle :size="18" />{{ error }}
      <button type="button" class="text-button" @click="load">重试</button>
    </div>
    <div v-if="loading" class="loading-state"><span class="loader" />加载配置…</div>

    <template v-else>
      <section class="settings-section">
        <div class="settings-section-title">
          <div class="section-icon"><ShieldCheck :size="19" /></div>
          <div><h2>Guard 策略</h2><p>请求审核的全局行为</p></div>
        </div>
        <div class="settings-fields">
          <div class="setting-row">
            <div><label for="guard-enabled">启用审核</label><p>关闭后所有请求直接转发到上游。</p></div>
            <label class="switch"><input id="guard-enabled" v-model="config.enabled" type="checkbox" /><span /></label>
          </div>
          <div class="setting-row">
            <div><label>运行模式</label><p>仅明确风险 Hash 或 AI reject 时阻断。</p></div>
            <div class="segmented-control"><button class="active" type="button">宽松模式</button></div>
          </div>
          <div class="setting-row">
            <div><label>未知客户端</label><p>未命中 User-Agent 规则时不进入审核。</p></div>
            <span class="readonly-value">默认放行</span>
          </div>
          <div class="setting-row">
            <div><label>普通事件</label><p>仅保存元数据，不包含指令原文。</p></div>
            <span class="readonly-value">保留 {{ config.event_retention_days }} 天</span>
          </div>
        </div>
      </section>

      <section class="settings-section">
        <div class="settings-section-title">
          <div class="section-icon orange"><Link2 :size="19" /></div>
          <div><h2>反向代理</h2><p>目标服务与请求边界</p></div>
        </div>
        <div class="settings-form-grid">
          <label class="field-label span-2" for="upstream-url">
            上游服务地址
            <input id="upstream-url" v-model="config.upstream_url" type="url" placeholder="http://upstream:8080" required />
            <span class="field-help">保存后立即用于新请求，无需重启容器。请填写 Guard 可访问的完整 HTTP(S) 地址。</span>
          </label>
          <label class="field-label" for="request-timeout">
            审核总超时（毫秒）
            <input id="request-timeout" v-model.number="config.request_timeout_ms" type="number" min="100" max="30000" step="100" />
          </label>
          <label class="field-label" for="body-limit">
            请求体上限（MB）
            <input id="body-limit" v-model.number="bodyLimitMB" type="number" min="1" max="64" />
          </label>
          <div class="field-label span-2">
            <span>受保护路径</span>
            <div v-for="protectedPath in config.protected_paths" :key="protectedPath" class="protected-path">
              <code>{{ protectedPath }}</code><span>精确匹配</span>
            </div>
            <span class="field-help">其他路径保持透明转发。</span>
          </div>
        </div>
      </section>

      <section class="settings-section">
        <div class="settings-section-title">
          <div class="section-icon gray"><Server :size="19" /></div>
          <div><h2>事件存储</h2><p>SQLite 本地记录策略</p></div>
        </div>
        <div class="settings-form-grid">
          <label class="field-label" for="retention-days">
            保留天数
            <input id="retention-days" v-model.number="config.event_retention_days" type="number" min="1" max="3650" />
          </label>
          <div class="storage-note"><KeyRound :size="18" /><div><strong>敏感字段保护</strong><span>节点密钥不会在接口响应中返回。</span></div></div>
        </div>
      </section>

      <div class="settings-savebar" aria-live="polite">
        <div>
          <span v-if="configDirty" class="unsaved-dot" />
          <strong>{{ configDirty ? 'Guard 配置有未保存的更改' : 'Guard 配置已同步' }}</strong>
          <small>{{ configDirty ? '保存后新请求立即生效' : '当前配置已生效' }}</small>
        </div>
        <div>
          <button type="button" class="secondary-button" :disabled="!configDirty || savingConfig" @click="resetConfig"><RefreshCw :size="15" />重置</button>
          <button type="button" class="primary-button" :disabled="!configDirty || savingConfig" :aria-busy="savingConfig" @click="saveConfig">
            <LoaderCircle v-if="savingConfig" class="spin" :size="16" /><Save v-else :size="16" />{{ savingConfig ? '保存中…' : '保存 Guard 配置' }}
          </button>
        </div>
      </div>

      <section class="settings-section ai-settings-section">
        <div class="settings-section-title">
          <div class="section-icon purple"><Zap :size="19" /></div>
          <div><h2>AI 审核节点</h2><p>OpenAI-compatible Chat Completions</p></div>
          <button type="button" class="secondary-button section-action" :disabled="testing || savingEndpoint" :aria-busy="testing" @click="testEndpoint">
            <LoaderCircle v-if="testing" class="spin" :size="16" /><TestTube2 v-else :size="16" />{{ testing ? '测试中…' : '测试连接' }}
          </button>
        </div>
        <div v-if="testResult" class="test-result" :class="{ success: testResult.ok, failed: !testResult.ok }" role="status">
          <Check v-if="testResult.ok" :size="17" /><AlertTriangle v-else :size="17" />
          <span>{{ testResult.message }}</span><strong v-if="testResult.latency != null">{{ testResult.latency }} ms</strong>
        </div>
        <div class="settings-form-grid">
          <label class="field-label span-2" for="ai-url">Base URL<input id="ai-url" v-model="endpoint.base_url" type="url" placeholder="https://api.example.com/v1" /></label>
          <label class="field-label" for="ai-model">模型<input id="ai-model" v-model="endpoint.model" placeholder="gpt-4.1-mini" /></label>
          <label class="field-label" for="ai-key">
            API Key <span v-if="endpoint.has_api_key" class="field-hint">已配置</span>
            <div class="input-with-action">
              <input id="ai-key" v-model="endpoint.api_key" :type="showKey ? 'text' : 'password'" autocomplete="new-password" :placeholder="endpoint.has_api_key ? '留空以保留现有密钥' : '输入节点密钥'" />
              <button type="button" :aria-label="showKey ? '隐藏密钥' : '显示密钥'" @click="showKey = !showKey"><EyeOff v-if="showKey" :size="16" /><Eye v-else :size="16" /></button>
            </div>
          </label>
          <label class="field-label" for="ai-timeout">单次超时（毫秒）<input id="ai-timeout" v-model.number="endpoint.timeout_ms" type="number" min="100" max="30000" step="100" /></label>
          <label class="field-label" for="ai-concurrency">最大并发<input id="ai-concurrency" v-model.number="endpoint.max_concurrency" type="number" min="1" max="256" /></label>
        </div>
        <div class="settings-section-footer" aria-live="polite">
          <span>{{ endpointDirty ? 'AI 节点有未保存的更改' : 'AI 节点配置已同步' }}</span>
          <div>
            <button type="button" class="secondary-button" :disabled="!endpointDirty || savingEndpoint" @click="resetEndpoint"><RefreshCw :size="15" />重置</button>
            <button type="button" class="primary-button" :disabled="!endpointDirty || savingEndpoint" :aria-busy="savingEndpoint" @click="saveEndpoint">
              <LoaderCircle v-if="savingEndpoint" class="spin" :size="16" /><Save v-else :size="16" />{{ savingEndpoint ? '保存中…' : '保存 AI 节点' }}
            </button>
          </div>
        </div>
      </section>

      <section class="settings-section ai-settings-section async-ai-section">
        <div class="settings-section-title">
          <div class="section-icon purple"><Zap :size="19" /></div>
          <div><h2>异步 AI 投票</h2><p>三个独立节点在请求完成后并行复核</p></div>
          <span class="readonly-value">风险 2/3 · 可信 2/3</span>
        </div>
        <div v-for="node in asyncNodes" :key="node.slot" class="async-node-card">
          <div class="async-node-heading"><strong>{{ node.slot }}</strong><span>{{ node.api_key ? '待保存新密钥' : node.has_api_key ? '密钥已配置' : '未配置密钥' }}</span><button type="button" class="secondary-button" :disabled="!node.base_url || !node.model" @click="testAsyncNode(node)"><TestTube2 :size="15" />测试</button></div>
          <div class="settings-form-grid">
            <label class="field-label">名称<input v-model="node.name" /></label>
            <label class="field-label">Base URL<input v-model="node.base_url" type="url" placeholder="https://api.example.com/v1" /></label>
            <label class="field-label">模型<input v-model="node.model" placeholder="guard-reviewer" /></label>
            <label class="field-label">API Key<div class="input-with-action"><input v-model="node.api_key" type="password" autocomplete="new-password" :placeholder="node.has_api_key ? '留空以保留现有密钥' : '输入节点密钥'" /></div></label>
            <label class="field-label">超时（毫秒）<input v-model.number="node.timeout_ms" type="number" min="100" max="30000" step="100" /></label>
            <label class="field-label checkbox-field"><input v-model="node.enabled" type="checkbox" />启用该节点</label>
          </div>
          <div v-if="asyncTestResult[node.slot]" class="test-result" :class="{ success: asyncTestResult[node.slot]?.ok, failed: !asyncTestResult[node.slot]?.ok }" role="status">
            <Check v-if="asyncTestResult[node.slot]?.ok" :size="17" /><AlertTriangle v-else :size="17" /><span>{{ asyncTestResult[node.slot]?.message }}</span><strong v-if="asyncTestResult[node.slot]?.latency != null">{{ asyncTestResult[node.slot]?.latency }} ms</strong>
          </div>
        </div>
        <div class="settings-section-footer" aria-live="polite">
          <span>{{ asyncNodesDirty ? '异步投票节点有未保存的更改' : '异步投票节点配置已同步' }}</span>
          <div>
            <button type="button" class="secondary-button" :disabled="!asyncNodesDirty || savingAsyncNodes" @click="resetAsyncNodes"><RefreshCw :size="15" />重置</button>
            <button type="button" class="primary-button" :disabled="!asyncNodesDirty || savingAsyncNodes" :aria-busy="savingAsyncNodes" @click="saveAsyncNodes"><LoaderCircle v-if="savingAsyncNodes" class="spin" :size="16" /><Save v-else :size="16" />{{ savingAsyncNodes ? '保存中…' : '保存三个节点' }}</button>
          </div>
        </div>
      </section>

      <section class="settings-section update-section">
        <div class="settings-section-title">
          <div class="section-icon update-icon"><Download :size="19" /></div>
          <div><h2>软件更新</h2><p>在线检查、升级与健康失败自动回滚</p></div>
          <button type="button" class="secondary-button section-action" :disabled="checkingUpdate" @click="loadUpdateStatus()"><RefreshCw :size="15" :class="{ spin: checkingUpdate }" />检查更新</button>
        </div>
        <div v-if="!updateStatus?.available" class="update-unavailable"><AlertTriangle :size="18" /><div><strong>更新服务未连接</strong><span>当前实例未安装主机更新代理，审核与代理功能不受影响。</span></div></div>
        <template v-else>
          <div class="update-grid">
            <div><span>当前版本</span><strong>{{ updateStatus.current_version || '未知' }}</strong><small>{{ shortImage(updateStatus.current_image) }}</small></div>
            <div><span>最新版本</span><strong>{{ updateStatus.latest_version || '检查失败' }}</strong><small>{{ updateStatus.latest_error || '来自 GitHub 正式发行版' }}</small></div>
            <div><span>任务状态</span><strong>{{ updateStatus.state === 'running' ? '执行中' : updateStatus.state === 'failed' ? '上次失败' : updateStatus.state === 'succeeded' ? '上次成功' : '空闲' }}</strong><small>{{ updateStatus.message || '尚未执行更新' }}</small></div>
          </div>
          <div v-if="updateStatus.state === 'running'" class="update-progress"><LoaderCircle class="spin" :size="17" /><span>{{ updateStatus.action === 'rollback' ? '正在回滚并等待健康检查…' : `正在更新到 ${updateStatus.target_version || updateStatus.latest_version}…` }}</span></div>
          <div class="settings-section-footer update-actions">
            <span>只允许官方 <code>abingooo/nocyber-guard</code> 镜像摘要；升级失败会自动恢复。</span>
            <div>
              <button type="button" class="secondary-button" :disabled="!updateStatus.rollback_available || updateStatus.state === 'running' || startingUpdate" @click="rollbackSystem"><RotateCcw :size="15" />回滚上个版本</button>
              <button type="button" class="primary-button" :disabled="!updateStatus.latest_version || updateStatus.state === 'running' || startingUpdate || isLatestVersion" @click="startUpdate"><Download :size="16" />{{ isLatestVersion ? '已是最新版' : '更新到最新版' }}</button>
            </div>
          </div>
        </template>
      </section>
    </template>
  </section>
</template>
