import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, ApiError } from '../api/client'

// One message for every 401: the server deliberately does not distinguish an
// unknown user, a wrong password and an unactivated account, so neither may we.
const GENERIC = 'Sign-in failed. Check your username and password.'

function messageFor(err: unknown): string {
  if (err instanceof ApiError && err.status === 429) {
    return 'Too many attempts. Please wait a minute and try again.'
  }
  if (err instanceof ApiError && err.status === 503) {
    return 'The server is busy. Please try again in a moment.'
  }
  if (err instanceof ApiError && err.status === 401) return GENERIC
  // A 5xx or an unreachable server says nothing about the account.
  return 'Sign-in is unavailable right now. Please try again shortly.'
}

export default function Login() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api('/api/login', { method: 'POST', body: { username, password }, redirectOn401: false })
      navigate('/fleet')
    } catch (err) {
      setError(messageFor(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="mx-auto mt-24 max-w-sm p-4">
      <h1 className="mb-4 text-xl font-semibold">Sign in to FleetGuard</h1>
      <form onSubmit={submit} className="space-y-3">
        <label className="block">
          <span className="text-sm">Username</span>
          <input className="mt-1 w-full rounded border p-2" value={username} autoComplete="username"
            onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label className="block">
          <span className="text-sm">Password</span>
          <input className="mt-1 w-full rounded border p-2" type="password" value={password}
            autoComplete="current-password" onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
        <button className="w-full rounded bg-slate-800 p-2 text-white disabled:opacity-50" disabled={busy}>
          Sign in
        </button>
      </form>
      <p className="mt-4 text-sm">
        No account? <Link className="underline" to="/register">Register</Link>
      </p>
    </main>
  )
}
