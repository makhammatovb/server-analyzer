import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, type CreatedServer } from '../api/client'
import InstallCommand from '../components/InstallCommand'

export default function AddServer() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [note, setNote] = useState('')
  const create = useMutation({
    mutationFn: () => api<CreatedServer>('/api/servers', { method: 'POST', body: { name, note } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fleet'] }),
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate()
  }

  if (create.data) {
    const { install_command, token, token_expires_at, server } = create.data
    return (
      <section>
        <h1 className="mb-2 text-xl font-semibold">Install the agent on {server.name}</h1>
        <InstallCommand command={install_command} token={token} expiresAt={token_expires_at} />
        <p className="mt-4 text-sm"><Link className="underline" to="/fleet">Back to servers</Link> — the server turns green once the agent connects.</p>
      </section>
    )
  }

  return (
    <section className="max-w-md">
      <h1 className="mb-3 text-xl font-semibold">Add server</h1>
      <form onSubmit={submit} className="space-y-3">
        <label className="block">
          <span className="text-sm">Name</span>
          <input className="mt-1 w-full rounded border p-2" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} />
        </label>
        <label className="block">
          <span className="text-sm">Note</span>
          <input className="mt-1 w-full rounded border p-2" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1024} />
        </label>
        {create.isError && <p role="alert" className="text-sm text-red-700">Could not add the server. Check the name and try again.</p>}
        <button className="rounded bg-slate-800 px-3 py-2 text-white disabled:opacity-50" disabled={create.isPending}>
          Add server
        </button>
      </form>
    </section>
  )
}
