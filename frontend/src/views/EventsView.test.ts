import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import EventsView from './EventsView.vue'

const mocks = vi.hoisted(() => ({
  listEvents: vi.fn(),
  getEvent: vi.fn(),
  deleteEvents: vi.fn(),
  deleteEvent: vi.fn(),
  getEventEvidence: vi.fn(),
  createHash: vi.fn(),
  toast: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  api: {
    listEvents: mocks.listEvents,
    getEvent: mocks.getEvent,
    deleteEvents: mocks.deleteEvents,
    deleteEvent: mocks.deleteEvent,
    getEventEvidence: mocks.getEventEvidence,
    createHash: mocks.createHash,
  },
  ApiError: class ApiError extends Error {},
}))

vi.mock('@/composables/toast', () => ({
  useToast: () => ({ show: mocks.toast }),
}))

describe('EventsView cleanup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.listEvents.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
    mocks.deleteEvents.mockResolvedValue({ deleted_events: 12, deleted_evidence: 2, wal_truncated: true })
  })

  it('opens the cleanup dialog and explicitly clears all events', async () => {
    const wrapper = mount(EventsView)
    await flushPromises()

    const cleanupButton = wrapper.findAll('button').find((button) => button.text().includes('清理事件'))
    expect(cleanupButton).toBeDefined()
    await cleanupButton!.trigger('click')

    const modal = wrapper.get('.cleanup-modal')
    expect(modal.text()).toContain('可信库、风险库、AI 节点和审核配置不会受到影响')
    await modal.get('select').setValue('all')
    expect(modal.text()).toContain('全部审核事件将被永久删除')
    await modal.trigger('submit')
    await flushPromises()

    expect(mocks.deleteEvents).toHaveBeenCalledWith('all', undefined)
    expect(mocks.listEvents).toHaveBeenCalledTimes(2)
    expect(mocks.toast).toHaveBeenCalledWith('已清理 12 条事件', expect.objectContaining({ detail: expect.stringContaining('2 条关联证据') }))
    expect(wrapper.find('.cleanup-modal').exists()).toBe(false)
  })
})

describe('EventsView review explanations', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    const event = {
      id: 42,
      request_id: 'request-42',
      created_at: '2026-09-23T10:00:00Z',
      path: '/v1/responses',
      decision: 'allow',
      action: 'audit',
      outcome: 'allow',
      reason: 'ai_pass',
      field_name: 'instructions',
      prompt_sha256: 'a'.repeat(64),
      ai_result: 'pass',
      ai_confidence: 0.98,
      ai_reason: 'This is a coherent first-party agent policy.',
      ai_category: 'benign_agent_template',
      audit_latency_ms: 132,
      ai_latency_ms: 120,
      upstream_accessed: true,
      evidence_available: false,
    }
    mocks.listEvents.mockResolvedValue({ items: [event], total: 1, page: 1, page_size: 20 })
    mocks.getEvent.mockResolvedValue({
      ...event,
      review_job: {
        id: 7,
        job_key: event.prompt_sha256,
        sha256: event.prompt_sha256,
        sampled: false,
        status: 'promoted',
        promotion: 'trusted',
        attempts: 1,
        created_at: '2026-09-23T10:00:01Z',
        completed_at: '2026-09-23T10:00:02Z',
      },
      async_votes: [
        { id: 1, job_id: 7, node_slot: 'async_1', result: 'pass', confidence: 0.98, reason: 'Complete legitimate tool policy.', category: 'benign_agent_template', latency_ms: 410, created_at: '2026-09-23T10:00:02Z' },
        { id: 2, job_id: 7, node_slot: 'async_2', result: 'pass', confidence: 0.96, reason: 'No malicious objective.', category: 'benign_agent_template', latency_ms: 530, created_at: '2026-09-23T10:00:02Z' },
        { id: 3, job_id: 7, node_slot: 'async_3', confidence: 0, latency_ms: 15000, error: 'ai_timeout', created_at: '2026-09-23T10:00:16Z' },
      ],
    })
  })

  it('loads and displays the full synchronous verdict and every async vote', async () => {
    const wrapper = mount(EventsView)
    await flushPromises()
    await wrapper.get('button[aria-label="查看详情"]').trigger('click')
    await flushPromises()

    expect(mocks.getEvent).toHaveBeenCalledWith(42)
    const drawer = wrapper.get('.detail-drawer')
    expect(drawer.text()).toContain('This is a coherent first-party agent policy.')
    expect(drawer.text()).toContain('benign_agent_template')
    expect(drawer.text()).toContain('异步节点投票（3）')
    expect(drawer.text()).toContain('Complete legitimate tool policy.')
    expect(drawer.text()).toContain('No malicious objective.')
    expect(drawer.text()).toContain('ai_timeout')
  })
})
