import { describe, expect, test } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { server } from '../test/server'
import { renderWithProviders } from '../test/render'
import Login from './Login'

function renderLogin() {
  return renderWithProviders(
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/fleet" element={<p>fleet page</p>} />
    </Routes>,
    '/login',
  )
}

async function fillAndSubmit() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText(/username/i), 'alice')
  await user.type(screen.getByLabelText(/password/i), 'hunter2hunter2')
  await user.click(screen.getByRole('button', { name: /sign in/i }))
}

describe('Login', () => {
  test('login submits credentials and redirects to /fleet on success', async () => {
    let body: unknown
    server.use(
      http.post('*/api/login', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json({ id: 'u1', username: 'alice', role: 'user', is_active: true })
      }),
    )
    renderLogin()
    await fillAndSubmit()

    expect(await screen.findByText('fleet page')).toBeInTheDocument()
    expect(body).toEqual({ username: 'alice', password: 'hunter2hunter2' })
  })

  test('login shows one generic message for any failure', async () => {
    server.use(http.post('*/api/login', () => new HttpResponse(null, { status: 401 })))
    renderLogin()
    await fillAndSubmit()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Sign-in failed. Check your username and password.')
    // Never confirm or deny that the account exists or is activated.
    expect(alert.textContent).not.toMatch(/no such user|not (yet )?active|unknown user|pending/i)
  })

  test('a rate limit or overload tells the user to wait, not that the password is wrong', async () => {
    server.use(http.post('*/api/login', () => new HttpResponse(null, { status: 429 })))
    renderLogin()
    await fillAndSubmit()
    expect(await screen.findByRole('alert')).toHaveTextContent(/too many attempts.*wait/i)

    server.use(http.post('*/api/login', () => new HttpResponse(null, { status: 503 })))
    await userEvent.setup().click(screen.getByRole('button', { name: /sign in/i }))
    expect(await screen.findByText(/busy.*try again/i)).toBeInTheDocument()
    expect(screen.queryByText(/check your username and password/i)).not.toBeInTheDocument()
  })

  test('links to the register screen', () => {
    renderLogin()
    expect(screen.getByRole('link', { name: /register/i })).toHaveAttribute('href', '/register')
  })
})
