import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type User } from '../api/client'

function PendingRow({ user }: { user: User }) {
  const qc = useQueryClient()
  const [role, setRole] = useState<'admin' | 'user'>('user')
  const activate = useMutation({
    mutationFn: () => api<void>(`/api/users/${user.id}/activate`, { method: 'POST', body: { role } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
  return (
    <li className="flex items-center gap-3 rounded border p-3">
      <span className="grow font-medium">{user.username}</span>
      <label className="text-sm">
        <span className="sr-only">Role for {user.username}</span>
        <select className="rounded border p-1" value={role} onChange={(e) => setRole(e.target.value as 'admin' | 'user')}>
          <option value="user">user</option>
          <option value="admin">admin</option>
        </select>
      </label>
      <button className="rounded bg-slate-800 px-3 py-1 text-white disabled:opacity-50" disabled={activate.isPending} onClick={() => activate.mutate()}>
        Activate
      </button>
      {activate.isError && <span role="alert" className="text-sm text-red-700">Failed</span>}
    </li>
  )
}

export default function Users() {
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<User[]>('/api/users') })
  if (users.isPending) return <p>Loading users…</p>
  if (users.isError) return <p role="alert" className="text-red-700">Could not load users.</p>
  const pending = users.data.filter((u) => !u.is_active)
  const active = users.data.filter((u) => u.is_active)

  return (
    <section>
      <h1 className="mb-3 text-xl font-semibold">Users</h1>
      <h2 className="mb-2 font-medium">Pending registrations</h2>
      {pending.length === 0 ? <p className="text-sm">No pending registrations.</p> : (
        <ul className="space-y-2">{pending.map((u) => <PendingRow key={u.id} user={u} />)}</ul>
      )}
      <h2 className="mb-2 mt-6 font-medium">Active users</h2>
      <ul className="space-y-1 text-sm">
        {active.map((u) => <li key={u.id}>{u.username} ({u.role})</li>)}
      </ul>
    </section>
  )
}
