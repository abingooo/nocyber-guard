<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ChevronLeft, ChevronRight, Copy, Eye, Filter, RefreshCw, Search, ShieldAlert, ShieldCheck, X } from 'lucide-vue-next'
import { api, ApiError } from '@/api/client'
import type { AuditEvent, EventEvidence, PageResult } from '@/types'
import { useToast } from '@/composables/toast'

const result = ref<PageResult<AuditEvent>>({ items: [], total: 0, page: 1, page_size: 20 })
const loading = ref(true)
const error = ref('')
const selected = ref<AuditEvent | null>(null)
const evidence = ref<EventEvidence | null>(null)
const evidenceLoading = ref(false)
const ruleContent = ref('')
const addingRule = ref<'trusted' | 'risk' | null>(null)
const ruleError = ref('')
const ruleNotice = ref('')
const showFilters = ref(false)
const query = reactive({ search: '', decision: '', from: '', to: '' })
const page = ref(1)
const toast = useToast()

function formatTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' })
}
function decisionLabel(value: string) {
  return ({ allow: '放行', block: '阻断' } as Record<string, string>)[value] || value
}
function outcomeLabel(value: string) {
  return ({ allow: '正常放行', block: '已阻断', fail_open: '故障放行' } as Record<string, string>)[value] || value
}
function actionLabel(value: string) {
  return ({ audit: '进入审核', bypass: '未覆盖旁路' } as Record<string, string>)[value] || value
}
function outcomeClass(event: AuditEvent) {
  return event.outcome === 'fail_open' ? 'bypass' : event.decision
}
function shortHash(value?: string) { return value ? `${value.slice(0, 10)}…${value.slice(-8)}` : '—' }

async function load() {
  loading.value = true
  error.value = ''
  try {
    result.value = await api.listEvents({ page: page.value, page_size: 20, query: query.search, decision: query.decision, from: query.from, to: query.to })
  } catch (requestError) {
    error.value = requestError instanceof ApiError ? requestError.message : '无法加载审核事件'
  } finally {
    loading.value = false
  }
}
function applyFilters() { page.value = 1; void load(); showFilters.value = false }
function clearFilters() { query.search = ''; query.decision = ''; query.from = ''; query.to = ''; applyFilters() }
function changePage(next: number) {
  if (next < 1 || next > Math.ceil(result.value.total / result.value.page_size)) return
  page.value = next
  void load()
}
async function openEvent(event: AuditEvent) {
  selected.value = event
  evidence.value = null
  ruleContent.value = ''
  ruleError.value = ''
  ruleNotice.value = ''
  if (event.evidence_available) {
    evidenceLoading.value = true
    try {
      evidence.value = await api.getEventEvidence(event.id)
      if (evidence.value && !evidence.value.partial && evidence.value.content) {
        ruleContent.value = evidence.value.content
      }
    } catch { evidence.value = null }
    finally { evidenceLoading.value = false }
  }
}
function closeDetail() { selected.value = null; evidence.value = null }
async function copy(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value)
    toast.show(`${label}已复制`, { tone: 'info' })
  } catch {
    toast.show('复制失败', { tone: 'error' })
  }
}
async function addRule(kind: 'trusted' | 'risk') {
  if (!selected.value?.prompt_sha256) return
  if (!ruleContent.value) {
    ruleError.value = '请先填写该 Hash 对应的完整原文'
    return
  }
  ruleError.value = ''
  ruleNotice.value = ''
  addingRule.value = kind
  try {
    await api.createHash(kind, {
      sha256: selected.value.prompt_sha256,
      label: `审核事件 #${selected.value.id}`,
      content: ruleContent.value,
    })
    ruleNotice.value = kind === 'risk' ? '已加入风险库' : '已加入可信库'
    toast.show(ruleNotice.value)
  } catch (requestError) {
    ruleError.value = requestError instanceof ApiError ? requestError.message : '请稍后重试'
    toast.show('添加规则失败', { detail: ruleError.value, tone: 'error' })
  } finally {
    addingRule.value = null
  }
}
onMounted(load)
</script>

<template>
  <section class="page-view">
    <div class="page-heading">
      <div>
        <p class="eyebrow">AUDIT LOG / TRACEABILITY</p>
        <h1>审核事件</h1>
        <p class="page-subtitle">按请求、客户端与决策结果检索审核记录。</p>
      </div>
      <div class="heading-actions">
        <button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="16" :class="{ spin: loading }" />刷新</button>
        <button class="primary-button" @click="showFilters = !showFilters"><Filter :size="16" />筛选</button>
      </div>
    </div>

    <div v-if="error" class="error-banner"><ShieldAlert :size="18" />{{ error }}<button class="text-button" @click="load">重试</button></div>

    <article v-if="showFilters" class="filter-panel panel">
      <div class="filter-grid">
        <label>搜索请求 / 哈希<input v-model="query.search" placeholder="输入关键词" @keyup.enter="applyFilters" /></label>
        <label>决策结果<select v-model="query.decision"><option value="">全部结果</option><option value="allow">放行</option><option value="block">阻断</option></select></label>
        <label>开始日期<input v-model="query.from" type="date" /></label>
        <label>结束日期<input v-model="query.to" type="date" /></label>
      </div>
      <div class="filter-actions">
        <button class="text-button" @click="clearFilters">清除条件</button>
        <button class="primary-button" @click="applyFilters"><Search :size="15" />应用筛选</button>
      </div>
    </article>

    <article class="panel table-panel">
      <div class="table-toolbar">
        <div class="result-count">共 <strong>{{ result.total }}</strong> 条事件</div>
        <div v-if="query.search || query.decision || query.from || query.to" class="filter-tags">
          <span v-if="query.decision">{{ decisionLabel(query.decision) }}<button @click="query.decision = ''; applyFilters()"><X :size="12" /></button></span>
          <span v-if="query.search">“{{ query.search }}”<button @click="query.search = ''; applyFilters()"><X :size="12" /></button></span>
          <span v-if="query.from">开始 {{ query.from }}<button @click="query.from = ''; applyFilters()"><X :size="12" /></button></span>
          <span v-if="query.to">结束 {{ query.to }}<button @click="query.to = ''; applyFilters()"><X :size="12" /></button></span>
        </div>
      </div>
      <div v-if="loading" class="loading-state compact"><span class="loader" />加载中…</div>
      <div v-else-if="!result.items.length" class="empty-state"><Search :size="28" /><strong>没有找到事件</strong><span>尝试调整筛选条件，或等待新的请求进入。</span></div>
      <div v-else class="responsive-table-wrap">
        <table class="data-table">
          <thead><tr><th>结果</th><th>时间</th><th>客户端 / 模型</th><th>原因</th><th>Prompt Hash</th><th>审核耗时</th><th aria-label="操作" /></tr></thead>
          <tbody>
            <tr v-for="event in result.items" :key="event.id">
              <td><span class="decision-badge" :class="`decision-${outcomeClass(event)}`"><ShieldAlert v-if="event.outcome !== 'allow'" :size="14" /><ShieldCheck v-else :size="14" />{{ outcomeLabel(event.outcome) }}</span></td>
              <td class="nowrap">{{ formatTime(event.created_at) }}</td>
              <td><strong>{{ event.client_profile || '未识别客户端' }}</strong><small class="table-sub">{{ event.model || '未知模型' }}</small></td>
              <td><span class="reason-cell">{{ event.reason || '—' }}</span><small v-if="event.field_name" class="table-sub">字段：{{ event.field_name }}</small></td>
              <td><button class="hash-button" :title="event.prompt_sha256" @click="event.prompt_sha256 && copy(event.prompt_sha256, 'Hash')"><code>{{ shortHash(event.prompt_sha256) }}</code><Copy v-if="event.prompt_sha256" :size="13" /></button></td>
              <td>{{ event.audit_latency_ms ?? event.latency_ms ?? '—' }}<span v-if="event.audit_latency_ms || event.latency_ms"> ms</span></td>
              <td><button class="icon-button table-action" title="查看详情" aria-label="查看详情" @click="openEvent(event)"><Eye :size="17" /></button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="result.total" class="pagination">
        <span>第 {{ page }} / {{ Math.max(1, Math.ceil(result.total / result.page_size)) }} 页</span>
        <div>
          <button class="icon-button" :disabled="page <= 1" aria-label="上一页" @click="changePage(page - 1)"><ChevronLeft :size="17" /></button>
          <button class="icon-button" :disabled="page >= Math.ceil(result.total / result.page_size)" aria-label="下一页" @click="changePage(page + 1)"><ChevronRight :size="17" /></button>
        </div>
      </div>
    </article>

    <div v-if="selected" class="drawer-scrim" @click.self="closeDetail">
      <aside class="detail-drawer">
        <div class="drawer-header">
          <div><p class="eyebrow">EVENT #{{ selected.id }}</p><h2>事件详情</h2></div>
          <button class="icon-button" aria-label="关闭详情" @click="closeDetail"><X :size="19" /></button>
        </div>
        <div class="drawer-decision" :class="`decision-${outcomeClass(selected)}`">
          <ShieldAlert v-if="selected.outcome !== 'allow'" :size="21" /><ShieldCheck v-else :size="21" />
          <div><strong>{{ outcomeLabel(selected.outcome) }}</strong><span>{{ selected.reason || '审核完成' }}</span></div>
        </div>
        <div v-if="selected.prompt_sha256" class="event-rule-editor">
          <label class="field-label rule-content-field" for="event-rule-content">
            规则完整原文
            <span class="field-hint">完整阻断证据会自动填入；否则请粘贴原文，保存时将校验 SHA-256</span>
            <textarea id="event-rule-content" v-model="ruleContent" rows="6" placeholder="填写与此 Prompt Hash 完全对应的原文" />
          </label>
          <div class="rule-actions">
            <button class="secondary-button" :disabled="addingRule !== null || evidenceLoading || !ruleContent" @click="addRule('trusted')"><ShieldCheck :size="16" />{{ addingRule === 'trusted' ? '添加中…' : '加入可信库' }}</button>
            <button class="secondary-button" :disabled="addingRule !== null || evidenceLoading || !ruleContent" @click="addRule('risk')"><ShieldAlert :size="16" />{{ addingRule === 'risk' ? '添加中…' : '加入风险库' }}</button>
          </div>
        </div>
        <div v-if="addingRule || ruleError || ruleNotice" class="rule-feedback" :class="{ failed: ruleError }" role="status" aria-live="polite">
          <span v-if="addingRule" class="loader" aria-hidden="true" />
          <ShieldAlert v-else-if="ruleError" :size="16" />
          <ShieldCheck v-else :size="16" />
          <span>{{ addingRule ? `正在加入${addingRule === 'risk' ? '风险库' : '可信库'}…` : ruleError || ruleNotice }}</span>
        </div>
        <dl class="detail-list">
          <div><dt>发生时间</dt><dd>{{ formatTime(selected.created_at) }}</dd></div>
          <div><dt>请求 ID</dt><dd><code>{{ selected.request_id || '—' }}</code><button v-if="selected.request_id" class="inline-copy" @click="copy(selected.request_id, '请求 ID')"><Copy :size="13" /></button></dd></div>
          <div><dt>请求路径</dt><dd><code>{{ selected.path || '—' }}</code></dd></div>
          <div><dt>处理方式</dt><dd>{{ actionLabel(selected.action) }}</dd></div>
          <div><dt>最终结果</dt><dd>{{ outcomeLabel(selected.outcome) }}</dd></div>
          <div><dt>访问上游</dt><dd>{{ selected.upstream_accessed ? '是' : '否' }}</dd></div>
          <div><dt>客户端</dt><dd>{{ selected.client_profile || '未识别客户端' }}</dd></div>
          <div><dt>User-Agent</dt><dd class="breakable">{{ selected.user_agent || '—' }}</dd></div>
          <div><dt>模型</dt><dd>{{ selected.model || '—' }}</dd></div>
          <div><dt>选中字段</dt><dd>{{ selected.field_name || '—' }}</dd></div>
          <div><dt>Prompt Hash</dt><dd class="breakable"><code>{{ selected.prompt_sha256 || '—' }}</code></dd></div>
          <div><dt>AI 结果</dt><dd>{{ selected.ai_result || '—' }}<span v-if="selected.ai_confidence != null">（置信度 {{ (selected.ai_confidence * 100).toFixed(0) }}%）</span></dd></div>
          <div><dt>审核 / AI 耗时</dt><dd>{{ selected.audit_latency_ms }} / {{ selected.ai_latency_ms }} ms</dd></div>
        </dl>
        <div class="evidence-section">
          <div class="section-label">审核证据</div>
          <div v-if="evidenceLoading" class="loading-state compact"><span class="loader" />读取证据…</div>
          <div v-else-if="evidence" class="evidence-box">
            <div class="evidence-meta"><span>{{ evidence.field_name }}{{ evidence.partial ? '（已截取首尾）' : '' }}</span><span>{{ evidence.captured_at ? formatTime(evidence.captured_at) : '' }}</span></div>
            <pre>{{ evidence.content }}</pre>
          </div>
          <p v-else class="muted">此事件没有可查看的证据。</p>
        </div>
      </aside>
    </div>
  </section>
</template>
