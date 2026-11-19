import { expect, test } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { server } from '../test/server'
import { renderWithProviders } from '../test/render'
import Register from './Register'

test('register success shows the activation-required notice', async () => {
  server.use(http.post('*/api/register', () => HttpResponse.json({ status: 'pending activation' }, { status: 202 })))
  renderWithProviders(<Register />)
  const user = userEvent.setup()
  await user.type(screen.getByLabelText(/username/i), 'alice')
  await user.type(screen.getByLabelText(/password/i), 'hunter2hunter2')
  await user.click(screen.getByRole('button', { name: /register/i }))

  const notice = await screen.findByRole('status')
  expect(notice).toHaveTextContent('your account must be activated by an administrator')
  // 202 is identical whether or not the name was taken: do not claim creation.
  expect(notice.textContent).not.toMatch(/account (was )?created|registered successfully/i)
})
