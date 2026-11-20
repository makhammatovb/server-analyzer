import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'

export default function Register() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api('/api/register', { method: 'POST', body: { username, password }, redirectOn401: false })
      setDone(true)
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 400
          ? 'That username or password is not acceptable. Check the length and try again.'
          : 'Registration could not be submitted. Please try again shortly.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="mx-auto mt-24 max-w-sm p-4">
      <h1 className="mb-4 text-xl font-semibold">Register</h1>
      {done ? (
        // The server answers 202 whether or not the name was free, so this
        // must not say the account was created.
        <p role="status" className="rounded border border-slate-300 bg-slate-50 p-3 text-sm">
          Registration submitted: your account must be activated by an administrator before you can sign in.
        </p>
      ) : (
        <form onSubmit={submit} className="space-y-3">
          <label className="block">
            <span className="text-sm">Username</span>
            <input className="mt-1 w-full rounded border p-2" value={username} autoComplete="username"
              onChange={(e) => setUsername(e.target.value)} required />
          </label>
          <label className="block">
            <span className="text-sm">Password</span>
            <input className="mt-1 w-full rounded border p-2" type="password" value={password}
              autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} required />
          </label>
          {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
          <button className="w-full rounded bg-slate-800 p-2 text-white disabled:opacity-50" disabled={busy}>
            Register
          </button>
        </form>
      )}
      <p className="mt-4 text-sm"><Link className="underline" to="/login">Back to sign in</Link></p>
    </main>
  )
}
