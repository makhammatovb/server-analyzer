import { afterEach, describe, expect, test, vi } from 'vitest'
import { QueryClient } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { server } from './test/server'
import { api } from './api/client'
import { installSessionExpiry } from './session'

afterEach(() => window.history.pushState({}, '', '/'))

function expire() {
  server.use(http.get('*/api/servers', () => new HttpResponse(null, { status: 401 })))
  return api('/api/servers').catch(() => {})
}

describe('installSessionExpiry (the handler main.tsx installs)', () => {
  test('a 401 clears every cached query and sends the browser to /login', async () => {
    const qc = new QueryClient()
    qc.setQueryData(['me'], { username: 'root' })
    qc.setQueryData(['fleet'], [{ name: 'web-1' }])
    const navigate = vi.fn()
    installSessionExpiry(qc, navigate)

    await expire()

    expect(qc.getQueryData(['me'])).toBeUndefined()
    expect(qc.getQueryData(['fleet'])).toBeUndefined()
    expect(navigate).toHaveBeenCalledExactlyOnceWith('/login')
  })

  test('on /login it still clears state but does not navigate again', async () => {
    window.history.pushState({}, '', '/login')
    const qc = new QueryClient()
    qc.setQueryData(['me'], { username: 'root' })
    const navigate = vi.fn()
    installSessionExpiry(qc, navigate)

    await expire()

    expect(qc.getQueryData(['me'])).toBeUndefined()
    expect(navigate).not.toHaveBeenCalled()
  })
})
