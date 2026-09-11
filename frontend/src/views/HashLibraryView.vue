<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Check, Copy, LoaderCircle, Plus, RefreshCw, ShieldAlert, ShieldCheck, ToggleLeft, ToggleRight, Trash2, X } from 'lucide-vue-next'
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
const form = ref({ sha256: '', label: '' })
const toast = useToast()
const isRisk = computed(() => props.kind === 'risk')
const title = computed(() => isRisk.value ? '风险库' : '可信库')
const description = computed(() => isRisk.value ? '命中后立即阻断请求，优先级高于其他审核结果。' : '已确认安全的 Prompt Hash 将跳过 AI 审核。')

function shortHash(value: string) { return `${value.slice(0, 14)}…${value.slice(-10)}` }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString('zh-CN') }
async function load() { loading.value = true; error.value = ''; try { entries.value = await api.listHashes(props.kind) } catch (requestError) { error.value = requestError instanceof ApiError ? requestError.message : '无法加载规则库' } finally { loading.value = false } }
function openCreate() { form.value = { sha256: '', label: '' }; dialogOpen.value = true }
function closeCreate() { if (!saving.value) dialogOpen.value = false }
async function create() { if (!/^[a-fA-F0-9]{64}$/.test(form.value.sha256.trim())) { toast.show('请输入 64 位 SHA-256', { tone: 'error' }); return }; saving.value = true; try { const created = await api.createHash(props.kind, { sha256: form.value.sha256.trim().toLowerCase(), label: form.value.label.trim() || (isRisk.value ? '手动风险规则' : '手动可信规则') }); entries.value.unshift(created); dialogOpen.value = false; toast.show('规则已添加') } catch (requestError) { toast.show('添加失败', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' }) } finally { saving.value = false } }
async function remove(entry: HashEntry) { if (!window.confirm(`确定删除“${entry.label}”吗？`)) return; try { await api.deleteHash(props.kind, entry.id); entries.value = entries.value.filter((item) => item.id !== entry.id); toast.show('规则已删除', { tone: 'info' }) } catch (requestError) { toast.show('删除失败', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' }) } }
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
    toast.show('状态更新失败', { detail: requestError instanceof ApiError ? requestError.message : '请稍后重试', tone: 'error' })
  } finally {
    toggling.value = null
  }
}
async function copyHash(value: string) { try { await navigator.clipboard.writeText(value); toast.show('Hash 已复制', { tone: 'info' }) } catch { toast.show('复制失败', { tone: 'error' }) } }
onMounted(load)
</script>

<template>
  <section class="page-view"><div class="page-heading"><div><p class="eyebrow">RULE LIBRARY / {{ isRisk ? 'BLOCKLIST' : 'ALLOWLIST' }}</p><h1>{{ title }}</h1><p class="page-subtitle">{{ description }}</p></div><div class="heading-actions"><button class="secondary-button" :disabled="loading" @click="load"><RefreshCw :size="16" :class="{ spin: loading }" />刷新</button><button class="primary-button" @click="openCreate"><Plus :size="16" />添加规则</button></div></div><div class="library-callout" :class="{ risk: isRisk }"><div class="callout-icon"><ShieldAlert v-if="isRisk" :size="19" /><ShieldCheck v-else :size="19" /></div><div><strong>{{ isRisk ? '风险规则优先匹配' : '可信规则快速通行' }}</strong><span>{{ isRisk ? '命中后不调用上游模型，直接返回安全策略响应。' : '命中后跳过 AI 节点，降低延迟并保留完整审计记录。' }}</span></div><span class="callout-count">{{ entries.length }} 条</span></div><div v-if="error" class="error-banner"><ShieldAlert :size="18" />{{ error }}<button class="text-button" @click="load">重试</button></div><article class="panel table-panel"><div v-if="loading" class="loading-state"><span class="loader" />加载规则…</div><div v-else-if="!entries.length" class="empty-state"><ShieldCheck :size="28" /><strong>规则库为空</strong><span>添加一条 SHA-256 规则后，匹配结果会在这里显示。</span><button class="secondary-button" @click="openCreate"><Plus :size="15" />添加第一条规则</button></div><div v-else class="responsive-table-wrap"><table class="data-table"><thead><tr><th>规则名称</th><th>SHA-256</th><th>来源</th><th>状态</th><th>创建时间</th><th aria-label="操作" /></tr></thead><tbody><tr v-for="entry in entries" :key="entry.id"><td><strong>{{ entry.label }}</strong><small class="table-sub">ID {{ entry.id }}</small></td><td><button class="hash-button" :title="entry.sha256" @click="copyHash(entry.sha256)"><code>{{ shortHash(entry.sha256) }}</code><Copy :size="13" /></button></td><td>{{ entry.source || '管理员添加' }}</td><td><button type="button" class="status-toggle" :class="entry.enabled ? 'status-on' : 'status-off'" :disabled="toggling !== null" :aria-pressed="entry.enabled" :aria-label="entry.enabled ? '停用规则' : '启用规则'" @click="toggle(entry)"><LoaderCircle v-if="toggling === entry.id" class="spin" :size="13" /><ToggleRight v-else-if="entry.enabled" :size="16" /><ToggleLeft v-else :size="16" /><span>{{ entry.enabled ? '已启用' : '已停用' }}</span></button></td><td>{{ formatTime(entry.created_at) }}</td><td><button class="icon-button danger-button" title="删除规则" aria-label="删除规则" @click="remove(entry)"><Trash2 :size="16" /></button></td></tr></tbody></table></div></article><div v-if="dialogOpen" class="modal-scrim" @click.self="closeCreate"><form class="modal-card" @submit.prevent="create"><div class="modal-header"><div><p class="eyebrow">NEW {{ isRisk ? 'RISK' : 'TRUSTED' }} HASH</p><h2>添加规则</h2></div><button type="button" class="icon-button" aria-label="关闭" @click="closeCreate"><X :size="18" /></button></div><label class="field-label" for="hash-label">规则名称<input id="hash-label" v-model="form.label" placeholder="例如：内部工具模板" /></label><label class="field-label" for="hash-value">SHA-256 <span class="field-hint">必须为 64 位十六进制</span><input id="hash-value" v-model="form.sha256" class="mono-input" placeholder="请输入 Prompt 的 SHA-256" maxlength="64" /></label><div class="modal-actions"><button type="button" class="secondary-button" @click="closeCreate">取消</button><button type="submit" class="primary-button" :disabled="saving"><Check :size="16" />{{ saving ? '保存中…' : '保存规则' }}</button></div></form></div></section>
</template>
