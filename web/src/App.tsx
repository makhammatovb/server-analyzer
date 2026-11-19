import { Link, Navigate, Outlet, Route, Routes } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from './api/client'
import { useMe } from './auth'
import Login from './routes/Login'
import Register from './routes/Register'
import Pending from './routes/Pending'
import Fleet from './routes/Fleet'
import AddServer from './routes/AddServer'
import Users from './routes/Users'

// Everything behind sign-in. A 401 from /api/me is handled by the API client
// (redirect to /login); here we only decide between the app and Pending.
function Shell() {
  const me = useMe()
  const qc = useQueryClient()
  if (me.isPending) return <p className="p-4">Loading…</p>
  if (me.isError) return <p role="alert" className="p-4 text-red-700">Could not reach the server.</p>
  if (!me.data.is_active) return <Pending />
  const isAdmin = me.data.role === 'admin'

  async function logout() {
    try {
      await api('/api/logout', { method: 'POST', redirectOn401: false })
    } finally {
      qc.clear()
      window.location.assign('/login')
    }
  }

  return (
    <div className="mx-auto max-w-3xl p-4">
      <nav className="mb-4 flex items-center gap-4 border-b pb-2 text-sm">
        <strong>FleetGuard</strong>
        <Link to="/fleet">Servers</Link>
        {isAdmin && <Link to="/servers/new">Add server</Link>}
        {isAdmin && <Link to="/users">Users</Link>}
        <span className="grow" />
        <span>{me.data.username}</span>
        <button className="underline" onClick={logout}>Sign out</button>
      </nav>
      <Outlet />
    </div>
  )
}

function AdminOnly() {
  const me = useMe()
  if (me.data && me.data.role !== 'admin') return <Navigate to="/fleet" replace />
  return <Outlet />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<Shell />}>
        <Route path="/fleet" element={<Fleet />} />
        <Route element={<AdminOnly />}>
          <Route path="/servers/new" element={<AddServer />} />
          <Route path="/users" element={<Users />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/fleet" replace />} />
    </Routes>
  )
}
