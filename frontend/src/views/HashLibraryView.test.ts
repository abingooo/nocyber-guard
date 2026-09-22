import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import HashLibraryView from './HashLibraryView.vue'

const mocks = vi.hoisted(() => ({ listHashes: vi.fn(), getHash: vi.fn(), toast: vi.fn() }))

vi.mock('@/api/client', () => ({
  api: {
    listHashes: mocks.listHashes,
    getHash: mocks.getHash,
    createHash: vi.fn(),
    updateHash: vi.fn(),
    deleteHash: vi.fn(),
  },
  ApiError: class ApiError extends Error {},
}))

vi.mock('@/composables/toast', () => ({ useToast: () => ({ show: mocks.toast }) }))

function entry(id: number, label: string) {
  return { id, label, sha256: String(id).repeat(64).slice(0, 64), content: '', content_available: true, enabled: true, created_at: '2026-09-22T00:00:00Z' }
}

describe('HashLibraryView route changes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.listHashes.mockImplementation(async (kind: 'trusted' | 'risk') =>
      kind === 'trusted' ? [entry(1, 'trusted one'), entry(2, 'trusted two'), entry(3, 'trusted three')] : [entry(4, 'risk only')],
    )
    mocks.getHash.mockImplementation(async (_kind: 'trusted' | 'risk', id: number) => ({ ...entry(id, `rule ${id}`), content: `plaintext ${id}` }))
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

  it('ignores a slower response from the previously selected library', async () => {
    let resolveTrusted!: (value: ReturnType<typeof entry>[]) => void
    mocks.listHashes.mockImplementation((kind: 'trusted' | 'risk') =>
      kind === 'trusted'
        ? new Promise((resolve) => { resolveTrusted = resolve })
        : Promise.resolve([entry(4, 'risk only')]),
    )
    const wrapper = mount(HashLibraryView, { props: { kind: 'trusted' } })
    await Promise.resolve()
    await wrapper.setProps({ kind: 'risk' })
    await flushPromises()
    expect(wrapper.text()).toContain('risk only')

    resolveTrusted([entry(1, 'late trusted')])
    await flushPromises()
    expect(wrapper.text()).toContain('risk only')
    expect(wrapper.text()).not.toContain('late trusted')
  })

  it('loads plaintext only after the administrator opens a rule', async () => {
    mocks.listHashes.mockResolvedValue([entry(8, 'lazy rule')])
    const wrapper = mount(HashLibraryView, { props: { kind: 'trusted' } })
    await flushPromises()
    expect(mocks.getHash).not.toHaveBeenCalled()
    await wrapper.get('button.rule-content-button').trigger('click')
    await flushPromises()
    expect(mocks.getHash).toHaveBeenCalledWith('trusted', 8)
    expect(wrapper.text()).toContain('plaintext 8')
  })
})
