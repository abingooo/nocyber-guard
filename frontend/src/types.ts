export type HealthState = 'healthy' | 'degraded' | 'error' | 'unknown'
export type GuardDecision = 'allow' | 'block'
export type GuardAction = 'audit' | 'bypass'
export type GuardOutcome = 'allow' | 'block' | 'fail_open'

export interface Overview {
  status: HealthState
  enabled: boolean
  mode: string
  uptime_seconds: number
  total_requests: number
  audited_requests: number
  blocked_requests: number
  bypassed_requests: number
  ai_configured: boolean
  ai_model?: string
  avg_audit_latency_ms: number
  avg_ai_latency_ms: number
  audit_latency_samples: number
  ai_latency_samples: number
  async_nodes_configured: number
  async_promotions: number
  last_event_at?: string
  recent_events: AuditEvent[]
  hourly?: Array<{ hour: string; total: number; blocked: number }>
}

export interface AuditEvent {
  id: number | string
  request_id: string
  created_at: string
  path: string
  decision: GuardDecision
  action: GuardAction
  outcome: GuardOutcome
  reason: string
  field_name?: string
  client_profile?: string
  user_agent?: string
  model?: string
  api_key_fingerprint?: string
  api_key_hint?: string
  prompt_sha256?: string
  ai_result?: string
  ai_confidence?: number
  latency_ms?: number
  audit_latency_ms: number
  ai_latency_ms: number
  upstream_accessed: boolean
  evidence_available?: boolean
}

export interface EventEvidence {
  event_id: number | string
  field_name: string
  content?: string
  partial: boolean
  captured_at?: string
}

export interface EventDeleteResult {
  deleted_events: number
  deleted_evidence: number
  wal_truncated: boolean
}

export interface PageResult<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface HashEntry {
  id: number | string
  sha256: string
  label: string
  content: string
  content_available?: boolean
  source?: string
  api_key_fingerprint?: string
  api_key_hint?: string
  api_key_seen_at?: string
  enabled: boolean
  created_at: string
}

export interface ClientMatcher {
  type: 'prefix' | 'regex' | 'exact'
  value: string
}

export interface ClientProfile {
  id: number | string
  name: string
  description?: string
  enabled: boolean
  priority: number
  matchers: ClientMatcher[]
  created_at?: string
  updated_at?: string
}

export interface GuardConfig {
  version: number
  enabled: boolean
  mode: 'permissive'
  upstream_url: string
  protected_paths: string[]
  admin_frame_ancestors: string[]
  request_timeout_ms: number
  max_body_bytes: number
  event_retention_days: number
  ai_endpoint?: AIEndpoint
  async_nodes?: AINode[]
  async_quorum?: {
    confidence: number
    risk: string
    trusted: string
  }
}

export interface AIEndpoint {
  base_url: string
  model: string
  api_key?: string
  has_api_key: boolean
  timeout_ms: number
  max_concurrency: number
}

export interface AINode {
  id?: number | string
  slot: 'async_1' | 'async_2' | 'async_3'
  name: string
  base_url: string
  model: string
  api_key?: string
  has_api_key: boolean
  timeout_ms: number
  enabled: boolean
}

export interface SystemUpdateStatus {
  available: boolean
  state: 'idle' | 'running' | 'succeeded' | 'failed' | string
  action?: 'update' | 'rollback' | string
  current_version: string
  latest_version?: string
  current_image?: string
  previous_image?: string
  rollback_available?: boolean
  target_version?: string
  message?: string
  started_at?: string
  completed_at?: string
  latest_error?: string
}

export interface LoginResponse {
  username?: string
  expires_at?: string
}

export interface ApiEnvelope<T> {
  data?: T
  message?: string
  error?: string | { message?: string; code?: string }
}
