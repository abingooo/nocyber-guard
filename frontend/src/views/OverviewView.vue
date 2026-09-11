<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Activity, ArrowDownRight, ArrowUpRight, Ban, CheckCircle2, Clock3, RefreshCw, ShieldAlert, ShieldCheck, Zap } from 'lucide-vue-next'
import { api, ApiError } from '@/api/client'
import type { AuditEvent, Overview } from '@/types'
import { useToast } from '@/composables/toast'

const data = ref<Overview | null>(null)
const loading = ref(true)
const error = ref('')
const toast = useToast()

const total = computed(() => data.value?.total_requests || 0)
const blockRate = computed(() => total.value ? `${(((data.value?.blocked_requests || 0) / total.value) * 100).toFixed(2)}%` : '0.00%')
const events = computed<AuditEvent[]>(() => data.value?.recent_events || [])
const bars = computed(() => {
  const source = data.value?.hourly || []
  if (source.length) {
    const max = Math.max(...source.map((item) => item.total), 1)
    return source.slice(-12).map((item) => ({ ...item, height: Math.max(5, Math.round((item.total / max) * 100)) }))
  }
  return Array.from({ length: 12 }, (_, index) => ({ hour: `${index}:00`, total: 0, blocked: 0, height: 5 }))
})

function formatNumber(value?: number) { return new Intl.NumberFormat('zh-CN').format(value || 0) }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
function decisionLabel(value: string) { return ({ allow: '放行', block: '阻断', bypass: '绕过', error: '异常', uncertain: '待定' } as Record<string, string>)[value] || value }
function decisionClass(value: string) { return `decision-${value}` }

async function load() {
  loading.value = true; error.value = ''
  try { data.value = await api.getOverview() } catch (requestError) { error.value = requestError instanceof ApiError ? requestError.message : '无法加载运行概览' }
  finally { loading.value = false }
}

async function refresh() { await load(); if (!error.value) toast.show('概览已刷新', { tone: 'info' }) }
onMounted(load)
</script>

<template>
  <section class="page-view">
    <div class="page-heading"><div><p class="eyebrow">OVERVIEW / REAL-TIME</p><h1>运行概览</h1><p class="page-subtitle">查看 Guard 当前健康状态与审核流量。</p></div><button class="secondary-button" :disabled="loading" @click="refresh"><RefreshCw :size="16" :class="{ spin: loading }" /> 刷新</button></div>
    <div v-if="error" class="error-banner"><ShieldAlert :size="18" /><span>{{ error }}</span><button class="text-button" @click="load">重试</button></div>
    <div v-if="loading && !data" class="loading-state"><span class="loader" />正在读取运行数据…</div>
    <template v-else>
      <div class="status-strip"><div class="status-primary"><span class="health-pulse" :class="`health-${data?.status || 'unknown'}`" /><div><strong>{{ data?.status === 'healthy' ? '系统运行正常' : data?.status === 'degraded' ? '系统运行降级' : '等待运行状态' }}</strong><span>配置版本 v{{ data?.config_version || 0 }} · {{ data?.mode === 'permissive' ? '宽松模式' : data?.mode || '未配置' }}</span></div></div><div class="status-metrics"><span><Clock3 :size="15" />运行 {{ Math.floor((data?.uptime_seconds || 0) / 3600) }}h {{ Math.floor(((data?.uptime_seconds || 0) % 3600) / 60) }}m</span><span><Zap :size="15" />AI {{ data?.ai_available ? '可用' : '不可用' }}</span></div></div>
      <div class="metric-grid">
        <article class="metric-card"><div class="metric-icon teal"><Activity :size="19" /></div><div class="metric-label">总请求数</div><strong class="metric-value">{{ formatNumber(total) }}</strong><span class="metric-foot"><ArrowUpRight :size="13" />累计请求</span></article>
        <article class="metric-card"><div class="metric-icon blue"><ShieldCheck :size="19" /></div><div class="metric-label">已审核</div><strong class="metric-value">{{ formatNumber(data?.audited_requests) }}</strong><span class="metric-foot">覆盖 {{ total ? ((data?.audited_requests || 0) / total * 100).toFixed(1) : '0.0' }}%</span></article>
        <article class="metric-card"><div class="metric-icon orange"><Ban :size="19" /></div><div class="metric-label">已阻断</div><strong class="metric-value">{{ formatNumber(data?.blocked_requests) }}</strong><span class="metric-foot negative"><ArrowDownRight :size="13" />风险率 {{ blockRate }}</span></article>
        <article class="metric-card"><div class="metric-icon purple"><Clock3 :size="19" /></div><div class="metric-label">平均响应</div><strong class="metric-value">{{ data?.ai_latency_ms || 0 }}<small>ms</small></strong><span class="metric-foot">AI 节点耗时</span></article>
      </div>
      <div class="overview-grid">
        <article class="panel traffic-panel"><div class="panel-heading"><div><h2>审核流量</h2><span>最近 12 个时间段</span></div><div class="legend"><i class="legend-total" />请求 <i class="legend-blocked" />阻断</div></div><div class="traffic-chart"><div v-for="bar in bars" :key="bar.hour" class="chart-column"><div class="bar-track"><span class="bar-total" :style="{ height: `${bar.height}%` }" /><span class="bar-blocked" :style="{ height: `${Math.max(3, bar.total ? bar.blocked / bar.total * bar.height : 3)}%` }" /></div><small>{{ bar.hour.slice(-5) }}</small></div></div></article>
        <article class="panel ai-panel"><div class="panel-heading"><div><h2>审核节点</h2><span>当前连接状态</span></div><span class="node-status" :class="{ good: data?.ai_available }"><i />{{ data?.ai_available ? '在线' : '离线' }}</span></div><div class="node-summary"><div class="node-avatar"><Zap :size="22" /></div><div><strong>OpenAI Compatible</strong><span>主审核节点</span></div></div><div class="node-stats"><div><span>平均延迟</span><strong>{{ data?.ai_latency_ms || 0 }} ms</strong></div><div><span>审核模式</span><strong>{{ data?.mode === 'permissive' ? '宽松放行' : data?.mode || '未设置' }}</strong></div></div><RouterLink to="/settings" class="panel-link">管理审核节点 <ArrowUpRight :size="15" /></RouterLink></article>
      </div>
      <article class="panel recent-panel"><div class="panel-heading"><div><h2>最近事件</h2><span>最新审核活动</span></div><RouterLink to="/events" class="panel-link">查看全部 <ArrowUpRight :size="15" /></RouterLink></div><div v-if="!events.length" class="empty-inline"><CheckCircle2 :size="18" />暂无审核事件</div><div v-else class="event-list"><div v-for="event in events.slice(0, 6)" :key="event.id" class="event-row"><span class="event-status" :class="decisionClass(event.decision)"><ShieldAlert v-if="event.decision === 'block'" :size="16" /><ShieldCheck v-else :size="16" /></span><div class="event-main"><strong>{{ event.reason || '审核完成' }}</strong><span>{{ event.client_profile || '未识别客户端' }} · {{ event.model || '未知模型' }}</span></div><span class="event-decision" :class="decisionClass(event.decision)">{{ decisionLabel(event.decision) }}</span><time>{{ formatTime(event.created_at) }}</time></div></div></article>
    </template>
  </section>
</template>
