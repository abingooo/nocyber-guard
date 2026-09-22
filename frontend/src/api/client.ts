import type {
  AIEndpoint,
  AINode,
  ApiEnvelope,
  AuditEvent,
  ClientProfile,
  EventDeleteResult,
  EventEvidence,
  GuardConfig,
  HashEntry,
  LoginResponse,
  Overview,
  PageResult,
} from '@/types'

const API_ROOT = '/api/v1'

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function unwrap<T>(payload: T | ApiEnvelope<T>): T {
  if (payload && typeof payload === 'object' && 'data' in payload) {
    return (payload as ApiEnvelope<T>).data as T
  }
  return payload as T
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  headers.set('Accept', 'application/json')
  const method = (init.method || 'GET').toUpperCase()
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && path !== '/auth/login') {
    const csrfToken = readCookie('ncg_csrf')
    if (csrfToken) headers.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers,
    credentials: 'include',
  })

  const contentType = response.headers.get('content-type') || ''
  const payload = contentType.includes('application/json')
    ? ((await response.json()) as ApiEnvelope<T> | T)
    : undefined

  if (!response.ok) {
    const envelope = payload as ApiEnvelope<T> | undefined
    const structuredError = envelope?.error
    const message =
      typeof structuredError === 'string'
        ? structuredError
        : structuredError?.message || envelope?.message || `请求失败（${response.status}）`
    throw new ApiError(message, response.status, typeof structuredError === 'object' ? structuredError.code : undefined)
  }

  return unwrap(payload as T | ApiEnvelope<T>)
}

function readCookie(name: string) {
  if (typeof document === 'undefined') return ''
  const prefix = `${encodeURIComponent(name)}=`
  const match = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
  if (!match) return ''
  try {
    return decodeURIComponent(match.slice(prefix.length))
  } catch {
    return ''
  }
}

function queryString(values: Record<string, string | number | undefined>) {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== '') params.set(key, String(value))
  })
  const query = params.toString()
  return query ? `?${query}` : ''
}

function configUpdateBody(config: GuardConfig) {
  return {
    version: config.version,
    enabled: config.enabled,
    mode: config.mode,
    upstream_url: config.upstream_url,
    protected_paths: [...config.protected_paths],
    request_timeout_ms: config.request_timeout_ms,
    max_body_bytes: config.max_body_bytes,
    event_retention_days: config.event_retention_days,
    expected_version: config.version,
  }
}

function aiEndpointWriteBody(endpoint: AIEndpoint) {
  return {
    base_url: endpoint.base_url.trim(),
    model: endpoint.model.trim(),
    api_key: endpoint.api_key || '',
    timeout_ms: endpoint.timeout_ms,
    max_concurrency: endpoint.max_concurrency,
  }
}

function aiNodeWriteBody(node: AINode) {
  return {
    slot: node.slot,
    name: node.name.trim(),
    base_url: node.base_url.trim(),
    model: node.model.trim(),
    api_key: node.api_key || '',
    timeout_ms: node.timeout_ms,
    enabled: node.enabled,
  }
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),

  getOverview: () => request<Overview>('/overview'),

  listEvents: (filters: {
    page?: number
    page_size?: number
    decision?: string
    query?: string
    from?: string
    to?: string
  }) => request<PageResult<AuditEvent>>(`/events${queryString(filters)}`),
  getEvent: (id: string | number) => request<AuditEvent>(`/events/${encodeURIComponent(id)}`),
  getEventEvidence: (id: string | number) =>
    request<EventEvidence>(`/events/${encodeURIComponent(id)}/evidence`),
  deleteEvent: (id: string | number) =>
    request<EventDeleteResult>(`/events/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  deleteEvents: (scope: 'all' | 'before', before?: string) =>
    request<EventDeleteResult>('/events', {
      method: 'DELETE',
      body: JSON.stringify({ scope, ...(scope === 'before' ? { before } : {}) }),
    }),

  listHashes: (kind: 'trusted' | 'risk') => request<HashEntry[]>(`/${kind}-hashes`),
  createHash: (kind: 'trusted' | 'risk', body: Pick<HashEntry, 'sha256' | 'label' | 'content'> & Partial<Pick<HashEntry, 'api_key_fingerprint' | 'api_key_hint'>>) =>
    request<HashEntry>(`/${kind}-hashes`, { method: 'POST', body: JSON.stringify(body) }),
  updateHash: (kind: 'trusted' | 'risk', id: string | number, body: Pick<HashEntry, 'label' | 'enabled'> & { content?: string }) =>
    request<HashEntry>(`/${kind}-hashes/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(body) }),
  deleteHash: (kind: 'trusted' | 'risk', id: string | number) =>
    request<void>(`/${kind}-hashes/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listClientProfiles: () => request<ClientProfile[]>('/client-profiles'),
  createClientProfile: (body: Omit<ClientProfile, 'id'>) =>
    request<ClientProfile>('/client-profiles', { method: 'POST', body: JSON.stringify(body) }),
  updateClientProfile: (id: string | number, body: Omit<ClientProfile, 'id'>) =>
    request<ClientProfile>(`/client-profiles/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  deleteClientProfile: (id: string | number) =>
    request<void>(`/client-profiles/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  getConfig: () => request<GuardConfig>('/config'),
  updateConfig: (config: GuardConfig) =>
    request<GuardConfig>('/config', {
      method: 'PUT',
      body: JSON.stringify(configUpdateBody(config)),
    }),
  updateAIEndpoint: (endpoint: AIEndpoint) =>
    request<AIEndpoint>('/ai-endpoint', { method: 'PUT', body: JSON.stringify(aiEndpointWriteBody(endpoint)) }),
  testAIEndpoint: (endpoint: AIEndpoint) =>
    request<{ ok: boolean; latency_ms?: number; message?: string }>('/ai-endpoint/test', {
      method: 'POST',
      body: JSON.stringify(aiEndpointWriteBody(endpoint)),
    }),
  updateAINodes: (nodes: AINode[]) =>
    request<{ items: AINode[] }>('/ai-nodes', {
      method: 'PUT',
      body: JSON.stringify({ nodes: nodes.map(aiNodeWriteBody) }),
    }),
  testAINode: (node: AINode) =>
    request<{ ok: boolean; latency_ms?: number; message?: string }>(`/ai-nodes/${encodeURIComponent(node.slot)}/test`, {
      method: 'POST',
      body: JSON.stringify(aiNodeWriteBody(node)),
    }),
}

export const apiInternals = { unwrap, queryString, readCookie, configUpdateBody, aiEndpointWriteBody, aiNodeWriteBody }
