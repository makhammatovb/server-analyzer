import { describe, expect, test } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { server } from '../test/server'
import { renderWithProviders } from '../test/render'
import { admin, plainUser, row } from '../test/fixtures'
import Fleet from './Fleet'

function serve(rows: unknown[], me: Record<string, unknown> = admin) {
  server.use(
    http.get('*/api/me', () => HttpResponse.json(me)),
    http.get('*/api/servers', () => HttpResponse.json(rows)),
  )
}

describe('Fleet', () => {
  test('fleet list shows a server as offline when last seen is stale', async () => {
    serve([row({ name: 'old-box', online: false, last_seen_at: new Date(Date.now() - 3 * 3_600_000).toISOString() })])
    renderWithProviders(<Fleet />)

    const card = (await screen.findByText('old-box')).closest('li')!
    expect(within(card).getByText('Offline')).toBeInTheDocument()
    expect(within(card).queryByText('Online')).not.toBeInTheDocument()
    expect(within(card).getByText(/3 hours ago/)).toBeInTheDocument()
  })

  test('fleet list sorts offline servers before online ones', async () => {
    serve([
      row({ id: '1', name: 'a-online', online: true }),
      row({ id: '2', name: 'b-offline', online: false }),
      row({ id: '3', name: 'c-online', online: true }),
      row({ id: '4', name: 'd-offline', online: false }),
    ])
    renderWithProviders(<Fleet />)
    await screen.findByText('a-online')
    const names = screen.getAllByRole('listitem').map((li) => within(li).getByRole('heading').textContent)
    // offline first, API order kept inside each group
    expect(names).toEqual(['b-offline', 'd-offline', 'a-online', 'c-online'])
  })

  test('a server that has never connected says so', async () => {
    serve([row({ name: 'fresh', online: false, last_seen_at: null, agent_version: '', cert_not_after: null })])
    renderWithProviders(<Fleet />)
    const card = (await screen.findByText('fresh')).closest('li')!
    expect(within(card).getByText(/never/i)).toBeInTheDocument()
  })

  test('an empty fleet points at adding a server', async () => {
    serve([])
    renderWithProviders(<Fleet />)
    expect(await screen.findByText(/no servers yet/i)).toBeInTheDocument()
  })

  test('decommission action is hidden for a non-admin user', async () => {
    let meServed = false
    serve([row({ name: 'web-1' })], plainUser)
    server.use(http.get('*/api/me', () => { meServed = true; return HttpResponse.json(plainUser) }))
    renderWithProviders(<Fleet />)
    await screen.findByText('web-1')
    // let /api/me resolve and re-render, so absence is not just "not loaded yet"
    await waitFor(() => expect(meServed).toBe(true))
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.queryByRole('button', { name: /decommission/i })).not.toBeInTheDocument()
  })

  test('decommission asks for confirmation before calling the endpoint', async () => {
    serve([row({ id: 's7', name: 'web-1' })])
    const calls: string[] = []
    server.use(
      http.post('*/api/servers/:id/decommission', ({ params }) => {
        calls.push(String(params.id))
        return new HttpResponse(null, { status: 204 })
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Fleet />)
    await user.click(await screen.findByRole('button', { name: /decommission/i }))

    // first click only asks
    expect(calls).toEqual([])
    expect(screen.getByText(/revokes its certificate/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /cancel/i }))
    expect(calls).toEqual([])

    await user.click(screen.getByRole('button', { name: /decommission/i }))
    await user.click(screen.getByRole('button', { name: /yes, decommission/i }))
    await waitFor(() => expect(calls).toEqual(['s7']))
    expect(calls).toEqual(['s7'])
  })
})
