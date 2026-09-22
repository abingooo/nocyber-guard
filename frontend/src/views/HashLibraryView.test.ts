import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import HashLibraryView from './HashLibraryView.vue'

const mocks = vi.hoisted(() => ({ listHashes: vi.fn(), toast: vi.fn() }))

vi.mock('@/api/client', () => ({
  api: {
    listHashes: mocks.listHashes,
    createHash: vi.fn(),
    updateHash: vi.fn(),
    deleteHash: vi.fn(),
  },
  ApiError: class ApiError extends Error {},
}))

vi.mock('@/composables/toast', () => ({ useToast: () => ({ show: mocks.toast }) }))

function entry(id: number, label: string) {
  return { id, label, sha256: String(id).repeat(64).slice(0, 64), content: label, enabled: true, created_at: '2026-09-22T00:00:00Z' }
}

describe('HashLibraryView route changes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.listHashes.mockImplementation(async (kind: 'trusted' | 'risk') =>
      kind === 'trusted' ? [entry(1, 'trusted one'), entry(2, 'trusted two'), entry(3, 'trusted three')] : [entry(4, 'risk only')],
    )
  })

  it('reloads and clears stale rows when the reused route changes kind', async () => {
    const wrapper = mount(HashLibraryView, { props: { kind: 'trusted' } })
    await flushPromises()
    expect(wrapper.text()).toContain('3 条')
    expect(wrapper.text()).toContain('trusted three')

    await wrapper.setProps({ kind: 'risk' })
    await flushPromises()
    expect(mocks.listHashes).toHaveBeenLastCalledWith('risk')
    expect(wrapper.text()).toContain('1 条')
    expect(wrapper.text()).toContain('risk only')
    expect(wrapper.text()).not.toContain('trusted three')
  })
})
