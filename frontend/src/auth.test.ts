import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  getSession: vi.fn(),
  getOverview: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  api: mocks,
  ApiError: class ApiError extends Error {
    constructor(message: string, public readonly status: number) { super(message) }
  },
}))

describe('authentication verification', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
    sessionStorage.clear()
    sessionStorage.setItem('nocyber.authenticated', '1')
    sessionStorage.setItem('nocyber.username', 'admin')
    mocks.getSession.mockResolvedValue({ username: 'admin' })
  })

  it('uses the lightweight session endpoint and caches successful verification', async () => {
    const { useAuth } = await import('./auth')
    const auth = useAuth()
    await expect(auth.verify()).resolves.toBe(true)
    await expect(auth.verify()).resolves.toBe(true)
    expect(mocks.getSession).toHaveBeenCalledOnce()
    expect(mocks.getOverview).not.toHaveBeenCalled()
  })
})
