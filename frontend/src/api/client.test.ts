import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, apiInternals } from './client'
import type { AIEndpoint, AINode, GuardConfig } from '@/types'

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('API client helpers', () => {
  it('unwraps response envelopes and leaves plain payloads intact', () => {
    expect(apiInternals.unwrap({ data: { ok: true } })).toEqual({ ok: true })
    expect(apiInternals.unwrap({ ok: true })).toEqual({ ok: true })
  })

  it('encodes query values and omits empty values', () => {
    expect(apiInternals.queryString({ page: 2, decision: 'block', query: '中文 / hash', to: '' }))
      .toBe('?page=2&decision=block&query=%E4%B8%AD%E6%96%87+%2F+hash')
    expect(apiInternals.queryString({ query: '', page: undefined })).toBe('')
  })
})

describe('API client request policy', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    document.cookie = 'ncg_csrf=; Max-Age=0; Path=/'
  })

  it('posts login credentials without a CSRF header', async () => {
    document.cookie = 'ncg_csrf=login-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: { username: 'abin' } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.login('abin', 'secret')).resolves.toEqual({ username: 'abin' })

    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = new Headers(init.headers)
    expect(url).toBe('/api/v1/auth/login')
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('include')
    expect(headers.get('X-CSRF-Token')).toBeNull()
    expect(JSON.parse(String(init.body))).toEqual({ username: 'abin', password: 'secret' })
  })

  it('adds the decoded CSRF cookie to non-login writes', async () => {
    document.cookie = 'ncg_csrf=csrf%20token; Path=/'
    const config: GuardConfig = {
      version: 7,
      enabled: true,
      mode: 'permissive',
      upstream_url: 'https://upstream.example.com',
      protected_paths: ['/v1/responses'],
      request_timeout_ms: 1800,
      max_body_bytes: 4 * 1024 * 1024,
      event_retention_days: 30,
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: config }))
    vi.stubGlobal('fetch', fetchMock)

    await api.updateConfig(config)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = new Headers(init.headers)
    expect(url).toBe('/api/v1/config')
    expect(init.method).toBe('PUT')
    expect(headers.get('X-CSRF-Token')).toBe('csrf token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(JSON.parse(String(init.body))).toEqual({
      version: 7,
      enabled: true,
      mode: 'permissive',
      upstream_url: 'https://upstream.example.com',
      protected_paths: ['/v1/responses'],
      request_timeout_ms: 1800,
      max_body_bytes: 4 * 1024 * 1024,
      event_retention_days: 30,
      expected_version: 7,
    })
  })

  it('does not send response-only config metadata back to the strict update endpoint', async () => {
    document.cookie = 'ncg_csrf=csrf-token; Path=/'
    const config: GuardConfig = {
      version: 9,
      enabled: true,
      mode: 'permissive',
      upstream_url: 'http://upstream:8080',
      protected_paths: ['/v1/responses', '/responses'],
      request_timeout_ms: 15000,
      max_body_bytes: 19 * 1024 * 1024,
      event_retention_days: 30,
      ai_endpoint: {
        base_url: 'https://ai.example.com/v1',
        model: 'guard-model',
        has_api_key: true,
        timeout_ms: 15000,
        max_concurrency: 16,
      },
      async_nodes: [],
      async_quorum: {
        confidence: 0.95,
        risk: '2/3 reject',
        trusted: '2/3 pass',
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: config }))
    vi.stubGlobal('fetch', fetchMock)

    await api.updateConfig(config)

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const body = JSON.parse(String(init.body))
    expect(body).toEqual({
      version: 9,
      enabled: true,
      mode: 'permissive',
      upstream_url: 'http://upstream:8080',
      protected_paths: ['/v1/responses', '/responses'],
      request_timeout_ms: 15000,
      max_body_bytes: 19 * 1024 * 1024,
      event_retention_days: 30,
      expected_version: 9,
    })
    expect(body).not.toHaveProperty('ai_endpoint')
    expect(body).not.toHaveProperty('async_nodes')
    expect(body).not.toHaveProperty('async_quorum')
  })

  it('allowlists synchronous AI fields for save and connectivity test requests', async () => {
    document.cookie = 'ncg_csrf=csrf-token; Path=/'
    const endpoint: AIEndpoint = {
      base_url: ' https://ai.example.com/v1 ',
      model: ' guard-model ',
      api_key: 'replacement-secret',
      has_api_key: true,
      timeout_ms: 15000,
      max_concurrency: 16,
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: endpoint }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }))
    vi.stubGlobal('fetch', fetchMock)

    await api.updateAIEndpoint(endpoint)
    await api.testAIEndpoint(endpoint)

    const expected = {
      base_url: 'https://ai.example.com/v1',
      model: 'guard-model',
      api_key: 'replacement-secret',
      timeout_ms: 15000,
      max_concurrency: 16,
    }
    expect(JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body))).toEqual(expected)
    expect(JSON.parse(String((fetchMock.mock.calls[1]?.[1] as RequestInit).body))).toEqual(expected)
    expect(JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body))).not.toHaveProperty('has_api_key')
  })

  it('allowlists asynchronous AI fields and tests the unsaved form values', async () => {
    document.cookie = 'ncg_csrf=csrf-token; Path=/'
    const nodes: AINode[] = (['async_1', 'async_2', 'async_3'] as const).map((slot, index) => ({
      id: index + 11,
      slot,
      name: ` node ${index + 1} `,
      base_url: ` https://node-${index + 1}.example.com/v1 `,
      model: ` model-${index + 1} `,
      api_key: `secret-${index + 1}`,
      has_api_key: true,
      timeout_ms: 15000,
      enabled: true,
    }))
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { items: nodes } }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }))
    vi.stubGlobal('fetch', fetchMock)

    await api.updateAINodes(nodes)
    await api.testAINode(nodes[0]!)

    const updateBody = JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body))
    expect(updateBody.nodes).toHaveLength(3)
    expect(updateBody.nodes[0]).toEqual({
      slot: 'async_1',
      name: 'node 1',
      base_url: 'https://node-1.example.com/v1',
      model: 'model-1',
      api_key: 'secret-1',
      timeout_ms: 15000,
      enabled: true,
    })
    expect(updateBody.nodes[0]).not.toHaveProperty('id')
    expect(updateBody.nodes[0]).not.toHaveProperty('has_api_key')

    const [testURL, testInit] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(testURL).toBe('/api/v1/ai-nodes/async_1/test')
    expect(JSON.parse(String(testInit.body))).toEqual(updateBody.nodes[0])
  })

  it('updates a hash with its enabled state', async () => {
    document.cookie = 'ncg_csrf=csrf-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: { id: 12, label: 'canary', enabled: false } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.updateHash('risk', 12, { label: 'canary', enabled: false })).resolves.toMatchObject({ enabled: false })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/risk-hashes/12')
    expect(init.method).toBe('PUT')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('csrf-token')
    expect(JSON.parse(String(init.body))).toEqual({ label: 'canary', enabled: false })
  })
})
