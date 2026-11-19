import { describe, expect, test, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../test/server'
import { api, ApiError, setUnauthorizedHandler } from './client'

describe('api client', () => {
  test('api client surfaces a 401 by redirecting to /login', async () => {
    server.use(http.get('*/api/servers', () => new HttpResponse(null, { status: 401 })))
    const onUnauthorized = vi.fn()
    setUnauthorizedHandler(onUnauthorized)

    await expect(api('/api/servers')).rejects.toBeInstanceOf(ApiError)
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  test('a 401 from login is a credentials failure, not a lost session', async () => {
    server.use(http.post('*/api/login', () => new HttpResponse(null, { status: 401 })))
    const onUnauthorized = vi.fn()
    setUnauthorizedHandler(onUnauthorized)

    await expect(
      api('/api/login', { method: 'POST', body: { username: 'a', password: 'b' }, redirectOn401: false }),
    ).rejects.toMatchObject({ status: 401 })
    expect(onUnauthorized).not.toHaveBeenCalled()
  })

  test('sends cookies, JSON bodies and parses JSON responses', async () => {
    let seen: { ct: string | null; body: unknown } | undefined
    const spy = vi.spyOn(globalThis, 'fetch')
    server.use(
      http.post('*/api/servers', async ({ request }) => {
        seen = { ct: request.headers.get('content-type'), body: await request.json() }
        return HttpResponse.json({ ok: 1 })
      }),
    )
    const out = await api<{ ok: number }>('/api/servers', { method: 'POST', body: { name: 'x' } })
    expect(out).toEqual({ ok: 1 })
    expect(seen).toEqual({ ct: 'application/json', body: { name: 'x' } })
    // MSW rebuilds the Request, so assert the cookie option on the fetch call itself.
    expect(spy.mock.calls[0][1]?.credentials).toBe('include')
    spy.mockRestore()
  })

  test('a 204 resolves without trying to parse a body', async () => {
    server.use(http.post('*/api/logout', () => new HttpResponse(null, { status: 204 })))
    await expect(api('/api/logout', { method: 'POST' })).resolves.toBeUndefined()
  })
})
