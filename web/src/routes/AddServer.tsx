import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, type CreatedServer } from '../api/client'

export default function AddServer() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [note, setNote] = useState('')
  const [copied, setCopied] = useState<'yes' | 'failed' | null>(null)
  const create = useMutation({
    mutationFn: () => api<CreatedServer>('/api/servers', { method: 'POST', body: { name, note } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fleet'] }),
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate()
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopied('yes')
    } catch {
      setCopied('failed')
    }
  }

  if (create.data) {
    const { install_command, token_expires_at, server } = create.data
    return (
      <section>
        <h1 className="mb-2 text-xl font-semibold">Install the agent on {server.name}</h1>
        <p className="mb-2 text-sm">Run this command as root on the server:</p>
        <pre data-testid="install-command" className="overflow-x-auto rounded bg-slate-900 p-3 text-sm text-slate-100">
          {install_command}
        </pre>
        <div className="mt-2 flex items-center gap-3">
          <button className="rounded bg-slate-800 px-3 py-1 text-white" onClick={() => copy(install_command)}>
            Copy
          </button>
          {copied === 'yes' && <span role="status" className="text-sm text-green-700">Copied</span>}
          {copied === 'failed' && <span role="status" className="text-sm text-red-700">Copy failed. Select the command and copy it by hand.</span>}
        </div>
        <p className="mt-3 text-sm">
          This command contains a single-use token and is shown only once; it cannot be retrieved later.
          It expires at <time data-testid="token-expiry" dateTime={token_expires_at}>{new Date(token_expires_at).toLocaleString()}</time>.
          If you lose it or it expires, issue a new token for this server.
        </p>
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
