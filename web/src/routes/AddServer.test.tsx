import { expect, test } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { server } from '../test/server'
import { renderWithProviders } from '../test/render'
import AddServer from './AddServer'

const cmd = "curl -sSL https://fg.example.com/install.sh | sudo bash -s -- --server-url=https://agents.example.com"
const tok = 'tok&<x>$1'


test('add server screen displays the returned install command verbatim', async () => {
  let body: unknown
  server.use(
    http.post('*/api/servers', async ({ request }) => {
      body = await request.json()
      return HttpResponse.json(
        {
          server: { id: 's9', name: 'db-1', note: 'primary', created_at: '2026-11-19T00:00:00Z' },
          install_command: cmd,
          token: tok,
          token_expires_at: '2026-11-19T13:00:00Z',
        },
        { status: 201 },
      )
    }),
  )
  const user = userEvent.setup()
  renderWithProviders(<AddServer />)
  await user.type(screen.getByLabelText(/name/i), 'db-1')
  await user.type(screen.getByLabelText(/note/i), 'primary')
  await user.click(screen.getByRole('button', { name: /add server/i }))

  const shown = await screen.findByTestId('install-command')
  expect(shown.textContent).toBe(cmd)
  expect(shown.textContent).not.toContain(tok) // the token is never on the command line
  expect(screen.getByTestId('enrol-token').textContent).toBe(tok)
  expect(body).toEqual({ name: 'db-1', note: 'primary' })
  // The token is single-use and shown once; say so and show when it lapses.
  expect(screen.getByText(/shown only once/i)).toBeInTheDocument()
  expect(screen.getByTestId('token-expiry')).toHaveTextContent(/2026/)

  await user.click(screen.getByRole('button', { name: /copy command/i }))
  expect(await navigator.clipboard.readText()).toBe(cmd)
  await user.click(screen.getByRole('button', { name: /copy token/i }))
  expect(await navigator.clipboard.readText()).toBe(tok)
})
