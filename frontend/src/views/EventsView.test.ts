import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import EventsView from './EventsView.vue'

const mocks = vi.hoisted(() => ({
  listEvents: vi.fn(),
  deleteEvents: vi.fn(),
  deleteEvent: vi.fn(),
  getEventEvidence: vi.fn(),
  createHash: vi.fn(),
  toast: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  api: {
    listEvents: mocks.listEvents,
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
