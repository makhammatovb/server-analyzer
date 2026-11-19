import { describe, expect, test } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { server } from '../test/server'
import { renderWithProviders } from '../test/render'
import { admin, plainUser } from '../test/fixtures'
import App from '../App'
import Users from './Users'

const pendingUser = { id: 'u9', username: 'newbie', role: 'user', is_active: false, created_at: '2026-11-18T00:00:00Z' }

describe('Users', () => {
  test('lists pending registrations and Activate posts the right id and role', async () => {
    const calls: { id: string; body: unknown }[] = []
    server.use(
      http.get('*/api/users', () => HttpResponse.json([admin, pendingUser])),
      http.post('*/api/users/:id/activate', async ({ params, request }) => {
        calls.push({ id: String(params.id), body: await request.json() })
        return new HttpResponse(null, { status: 204 })
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Users />)

    const row = (await screen.findByText('newbie')).closest('li')!
    expect(screen.getAllByRole('button', { name: /activate/i })).toHaveLength(1)

    await user.selectOptions(within(row).getByLabelText(/role for newbie/i), 'admin')
    await user.click(within(row).getByRole('button', { name: /activate/i }))

    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls).toEqual([{ id: 'u9', body: { role: 'admin' } }])
  })

  test('a successful activation refreshes the list so no stale row invites a second click', async () => {
    let activated = false
    let activateCalls = 0
    server.use(
      http.get('*/api/users', () =>
        HttpResponse.json(activated ? [admin, { ...pendingUser, is_active: true }] : [admin, pendingUser]),
      ),
      http.post('*/api/users/:id/activate', () => {
        activateCalls++
        activated = true
        return new HttpResponse(null, { status: 204 })
      }),
    )
    renderWithProviders(<Users />)
    await userEvent.setup().click(await screen.findByRole('button', { name: /activate/i }))

    await screen.findByText(/no pending registrations/i)
    expect(screen.queryByRole('button', { name: /activate/i })).not.toBeInTheDocument()
    expect(screen.getByText(/newbie \(user\)/)).toBeInTheDocument() // moved to active
    expect(activateCalls).toBe(1)
  })
})

describe('Users, concurrent activation', () => {
  test('a failed activation (another admin got there first) still refreshes the stale row away', async () => {
    let activated = false
    server.use(
      http.get('*/api/users', () =>
        HttpResponse.json(activated ? [admin, { ...pendingUser, is_active: true }] : [admin, pendingUser]),
      ),
      http.post('*/api/users/:id/activate', () => {
        activated = true // someone else already did it
        return new HttpResponse(null, { status: 404 })
      }),
    )
    renderWithProviders(<Users />)
    await userEvent.setup().click(await screen.findByRole('button', { name: /activate/i }))

    await screen.findByText(/no pending registrations/i)
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument()
  })
})

describe('routing', () => {
  test('the Activate control is absent for a non-admin', async () => {
    server.use(
      http.get('*/api/me', () => HttpResponse.json(plainUser)),
      http.get('*/api/users', () => new HttpResponse(null, { status: 403 })),
      http.get('*/api/servers', () => HttpResponse.json([])),
    )
    renderWithProviders(<App />, '/users')

    // a non-admin is sent to the fleet list, never shown the users screen
    expect(await screen.findByText(/no servers yet/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /activate/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /^users$/i })).not.toBeInTheDocument()
  })

  test('/api/me reporting is_active:false lands on Pending, not Fleet', async () => {
    let fleetRequested = false
    server.use(
      http.get('*/api/me', () => HttpResponse.json({ ...plainUser, is_active: false })),
      http.get('*/api/servers', () => {
        fleetRequested = true
        return HttpResponse.json([])
      }),
    )
    renderWithProviders(<App />, '/fleet')

    expect(await screen.findByText(/waiting for activation/i)).toBeInTheDocument()
    expect(screen.queryByText(/no servers yet/i)).not.toBeInTheDocument()
    expect(fleetRequested).toBe(false)
  })

  test('Pending offers a way to sign out', async () => {
    let loggedOut = false
    server.use(
      http.get('*/api/me', () => HttpResponse.json({ ...plainUser, is_active: false })),
      http.post('*/api/logout', () => {
        loggedOut = true
        return new HttpResponse(null, { status: 204 })
      }),
    )
    renderWithProviders(<App />, '/fleet')
    await userEvent.setup().click(await screen.findByRole('button', { name: /sign out/i }))
    await waitFor(() => expect(loggedOut).toBe(true))
  })
})
