<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  Check,
  Copy,
  Eye,
  FilePlus2,
  LoaderCircle,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ToggleLeft,
  ToggleRight,
  Trash2,
  X,
} from 'lucide-vue-next'
import { api, ApiError } from '@/api/client'
import type { HashEntry } from '@/types'
import { useToast } from '@/composables/toast'

const props = defineProps<{ kind: 'trusted' | 'risk' }>()
const entries = ref<HashEntry[]>([])
const loading = ref(true)
const error = ref('')
const dialogOpen = ref(false)
const saving = ref(false)
const toggling = ref<number | string | null>(null)
const form = ref({ sha256: '', label: '', content: '' })
const selected = ref<HashEntry | null>(null)
const contentDraft = ref('')
const contentSaving = ref(false)
const toast = useToast()
const isRisk = computed(() => props.kind === 'risk')
const title = computed(() => (isRisk.value ? '风险库' : '可信库'))
const description = computed(() =>
  isRisk.value ? '命中后立即阻断请求，优先级高于其他审核结果。' : '已确认安全的 Prompt Hash 将跳过 AI 审核。',
)

function shortHash(value: string) {
  return `${value.slice(0, 14)}…${value.slice(-10)}`
}

function formatTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString('zh-CN')
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    entries.value = await api.listHashes(props.kind)
  } catch (requestError) {
    error.value = requestError instanceof ApiError ? requestError.message : '无法加载规则库'
  } finally {
    loading.value = false
  }
}

function openCreate() {
  form.value = { sha256: '', label: '', content: '' }
  dialogOpen.value = true
}

function closeCreate() {
  if (!saving.value) dialogOpen.value = false
}

async function create() {
  const suppliedHash = form.value.sha256.trim().toLowerCase()
  if (!form.value.content) {
    toast.show('请输入规则对应的完整原文', { tone: 'error' })
    return
  }
  if (suppliedHash && !/^[a-f0-9]{64}$/.test(suppliedHash)) {
    toast.show('SHA-256 必须为 64 位十六进制，或留空自动计算', { tone: 'error' })
    return
  }
  saving.value = true
  try {
    const created = await api.createHash(props.kind, {
      sha256: suppliedHash,
      label: form.value.label.trim() || (isRisk.value ? '手动风险规则' : '手动可信规则'),
      content: form.value.content,
    })
    const existing = entries.value.findIndex((entry) => entry.id === created.id)
    if (existing >= 0) entries.value.splice(existing, 1)
    entries.value.unshift(created)
    dialogOpen.value = false
    toast.show('规则及原文已保存')
  } catch (requestError) {
    toast.show('添加失败', {
      detail: requestError instanceof ApiError ? requestError.message : '请稍后重试',
      tone: 'error',
    })
  } finally {
    saving.value = false
  }
}

function openContent(entry: HashEntry) {
  selected.value = entry
  contentDraft.value = entry.content || ''
}

function closeContent() {
  if (!contentSaving.value) selected.value = null
}

async function backfillContent() {
  const entry = selected.value
  if (!entry || entry.content) return
  if (!contentDraft.value) {
    toast.show('请输入与该 SHA-256 对应的完整原文', { tone: 'error' })
    return
  }
  contentSaving.value = true
  try {
    const updated = await api.updateHash(props.kind, entry.id, {
      label: entry.label,
      enabled: entry.enabled,
      content: contentDraft.value,
    })
    Object.assign(entry, updated)
    contentDraft.value = updated.content
    toast.show('原文已补录')
  } catch (requestError) {
    toast.show('原文补录失败', {
      detail: requestError instanceof ApiError ? requestError.message : '请确认原文与 SHA-256 完全对应',
      tone: 'error',
    })
  } finally {
    contentSaving.value = false
  }
}

async function remove(entry: HashEntry) {
  if (!window.confirm(`确定删除“${entry.label}”吗？`)) return
  try {
    await api.deleteHash(props.kind, entry.id)
    entries.value = entries.value.filter((item) => item.id !== entry.id)
    toast.show('规则已删除', { tone: 'info' })
  } catch (requestError) {
    toast.show('删除失败', {
      detail: requestError instanceof ApiError ? requestError.message : '请稍后重试',
      tone: 'error',
    })
  }
}

async function toggle(entry: HashEntry) {
  if (toggling.value !== null) return
  toggling.value = entry.id
  const previous = entry.enabled
  entry.enabled = !previous
  try {
    const updated = await api.updateHash(props.kind, entry.id, { label: entry.label, enabled: entry.enabled })
    Object.assign(entry, updated)
    toast.show(entry.enabled ? '规则已启用' : '规则已停用', { tone: 'info' })
  } catch (requestError) {
    entry.enabled = previous
    toast.show('状态更新失败', {
      detail: requestError instanceof ApiError ? requestError.message : '请稍后重试',
      tone: 'error',
    })
  } finally {
    toggling.value = null
  }
}

async function copyText(value: string, message: string) {
  try {
    await navigator.clipboard.writeText(value)
    toast.show(message, { tone: 'info' })
  } catch {
    toast.show('复制失败', { tone: 'error' })
  }
}

onMounted(load)
</script>

<template>
  <section class="page-view">
    <div class="page-heading">
      <div>
        <p class="eyebrow">RULE LIBRARY / {{ isRisk ? 'BLOCKLIST' : 'ALLOWLIST' }}</p>
        <h1>{{ title }}</h1>
        <p class="page-subtitle">{{ description }}</p>
      </div>
      <div class="heading-actions">
        <button class="secondary-button" :disabled="loading" @click="load">
          <RefreshCw :size="16" :class="{ spin: loading }" />刷新
        </button>
        <button class="primary-button" @click="openCreate"><Plus :size="16" />添加规则</button>
      </div>
    </div>

    <div class="library-callout" :class="{ risk: isRisk }">
      <div class="callout-icon">
        <ShieldAlert v-if="isRisk" :size="19" />
        <ShieldCheck v-else :size="19" />
      </div>
      <div>
        <strong>{{ isRisk ? '风险规则优先匹配' : '可信规则快速通行' }}</strong>
        <span>规则库长期保存 SHA-256 及其完整原文，登录后台即可直接查看。</span>
      </div>
      <span class="callout-count">{{ entries.length }} 条</span>
    </div>

    <div v-if="error" class="error-banner">
      <ShieldAlert :size="18" />{{ error }}<button class="text-button" @click="load">重试</button>
    </div>

    <article class="panel table-panel">
      <div v-if="loading" class="loading-state"><span class="loader" />加载规则…</div>
      <div v-else-if="!entries.length" class="empty-state">
        <ShieldCheck :size="28" />
        <strong>规则库为空</strong>
        <span>添加原文后，系统会自动计算 SHA-256 并保存。</span>
        <button class="secondary-button" @click="openCreate"><Plus :size="15" />添加第一条规则</button>
      </div>
      <div v-else class="responsive-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>规则名称</th>
              <th>SHA-256</th>
              <th>原文</th>
              <th>来源</th>
              <th>状态</th>
              <th>创建时间</th>
              <th aria-label="操作" />
            </tr>
          </thead>
          <tbody>
            <tr v-for="entry in entries" :key="entry.id">
              <td><strong>{{ entry.label }}</strong><small class="table-sub">ID {{ entry.id }}</small></td>
              <td>
                <button class="hash-button" :title="entry.sha256" @click="copyText(entry.sha256, 'Hash 已复制')">
                  <code>{{ shortHash(entry.sha256) }}</code><Copy :size="13" />
                </button>
              </td>
              <td>
                <button class="text-button rule-content-button" @click="openContent(entry)">
                  <Eye v-if="entry.content" :size="15" />
                  <FilePlus2 v-else :size="15" />
                  {{ entry.content ? '查看原文' : '补录原文' }}
                </button>
              </td>
              <td>{{ entry.source || '管理员添加' }}</td>
              <td>
                <button
                  type="button"
                  class="status-toggle"
                  :class="entry.enabled ? 'status-on' : 'status-off'"
                  :disabled="toggling !== null"
                  :aria-pressed="entry.enabled"
                  :aria-label="entry.enabled ? '停用规则' : '启用规则'"
                  @click="toggle(entry)"
                >
                  <LoaderCircle v-if="toggling === entry.id" class="spin" :size="13" />
                  <ToggleRight v-else-if="entry.enabled" :size="16" />
                  <ToggleLeft v-else :size="16" />
                  <span>{{ entry.enabled ? '已启用' : '已停用' }}</span>
                </button>
              </td>
              <td>{{ formatTime(entry.created_at) }}</td>
              <td>
                <button class="icon-button danger-button" title="删除规则" aria-label="删除规则" @click="remove(entry)">
                  <Trash2 :size="16" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>

    <div v-if="dialogOpen" class="modal-scrim" @click.self="closeCreate">
      <form class="modal-card wide" @submit.prevent="create">
        <div class="modal-header">
          <div><p class="eyebrow">NEW {{ isRisk ? 'RISK' : 'TRUSTED' }} RULE</p><h2>添加规则</h2></div>
          <button type="button" class="icon-button" aria-label="关闭" @click="closeCreate"><X :size="18" /></button>
        </div>
        <label class="field-label" for="hash-label">
          规则名称
          <input id="hash-label" v-model="form.label" placeholder="例如：内部工具模板" />
        </label>
        <label class="field-label rule-content-field" for="hash-content">
          完整原文 <span class="field-hint">按原样保存；空白、换行都会影响 Hash</span>
          <textarea id="hash-content" v-model="form.content" rows="10" placeholder="粘贴完整指令原文" />
        </label>
        <label class="field-label" for="hash-value">
          SHA-256（可选校验）
          <span class="field-hint">留空由服务端自动计算；填写后必须与原文完全匹配</span>
          <input id="hash-value" v-model="form.sha256" class="mono-input" placeholder="留空自动计算" maxlength="64" />
        </label>
        <div class="modal-actions">
          <button type="button" class="secondary-button" @click="closeCreate">取消</button>
          <button type="submit" class="primary-button" :disabled="saving">
            <Check :size="16" />{{ saving ? '保存中…' : '保存规则与原文' }}
          </button>
        </div>
      </form>
    </div>

    <div v-if="selected" class="modal-scrim" @click.self="closeContent">
      <section class="modal-card wide" aria-label="规则原文">
        <div class="modal-header">
          <div><p class="eyebrow">RULE PLAINTEXT</p><h2>{{ selected.label }}</h2></div>
          <button type="button" class="icon-button" aria-label="关闭" @click="closeContent"><X :size="18" /></button>
        </div>
        <div class="rule-content-meta">
          <code>{{ selected.sha256 }}</code>
          <button class="text-button" @click="copyText(selected.sha256, 'Hash 已复制')"><Copy :size="14" />复制 Hash</button>
        </div>
        <div v-if="selected.content" class="evidence-box rule-content-preview">
          <div class="evidence-meta"><span>完整原文</span><span>{{ selected.content.length }} 字符</span></div>
          <pre>{{ selected.content }}</pre>
        </div>
        <template v-else>
          <div class="warning-banner">
            <ShieldAlert :size="17" />此历史规则创建时只保存了 Hash。粘贴原文后会校验 SHA-256 并永久保存。
          </div>
          <label class="field-label rule-content-field" for="backfill-content">
            补录完整原文
            <textarea id="backfill-content" v-model="contentDraft" rows="12" placeholder="粘贴与该 Hash 对应的完整原文" />
          </label>
        </template>
        <div class="modal-actions">
          <button v-if="selected.content" class="secondary-button" @click="copyText(selected.content, '原文已复制')">
            <Copy :size="15" />复制原文
          </button>
          <button v-else class="primary-button" :disabled="contentSaving" @click="backfillContent">
            <Check :size="15" />{{ contentSaving ? '校验并保存中…' : '校验并保存原文' }}
          </button>
        </div>
      </section>
    </div>
  </section>
</template>
