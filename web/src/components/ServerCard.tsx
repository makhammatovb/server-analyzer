import { useState } from 'react'
import type { FleetRow } from '../api/client'
import { daysUntil, relativeTime } from '../lib'

interface Props {
  server: FleetRow
  isAdmin: boolean
  decommissioning: boolean
  onDecommission: (id: string) => void
}

function certExpiry(iso: string | null) {
  if (!iso) return { text: 'none yet', warn: false }
  const days = daysUntil(iso)
  const date = new Date(iso).toISOString().slice(0, 10)
  if (days < 0) return { text: `${date} (expired)`, warn: true }
  return { text: `${date} (${days} days left)`, warn: days < 14 }
}

export default function ServerCard({ server, isAdmin, decommissioning, onDecommission }: Props) {
  const [confirming, setConfirming] = useState(false)
  const cert = certExpiry(server.cert_not_after)

  return (
    <li className={`rounded border p-3 ${server.online ? 'border-slate-300' : 'border-red-400 bg-red-50'}`}>
      <div className="flex items-center justify-between gap-2">
        <h2 className="font-medium">{server.name}</h2>
        <span className={`text-sm font-semibold ${server.online ? 'text-green-700' : 'text-red-700'}`}>
          <span aria-hidden>{server.online ? '● ' : '○ '}</span>
          {server.online ? 'Online' : 'Offline'}
        </span>
      </div>
      {server.note && <p className="text-sm text-slate-600">{server.note}</p>}
      <dl className="mt-2 grid grid-cols-[8rem_1fr] gap-y-1 text-sm">
        <dt className="text-slate-500">Last seen</dt>
        <dd>{relativeTime(server.last_seen_at)}</dd>
        <dt className="text-slate-500">Agent version</dt>
        <dd>{server.agent_version || 'unknown'}</dd>
        <dt className="text-slate-500">Certificate expires</dt>
        <dd className={cert.warn ? 'font-semibold text-red-700' : ''}>{cert.text}</dd>
      </dl>
      {isAdmin && (
        <div className="mt-3 text-sm">
          {confirming ? (
            <div role="group" aria-label={`Confirm decommission of ${server.name}`}>
              <p className="mb-2">
                Decommissioning {server.name} revokes its certificate and removes it from this list.
                It cannot be undone; the agent would have to be enrolled again.
              </p>
              <button
                className="mr-2 rounded bg-red-700 px-3 py-1 text-white disabled:opacity-50"
                disabled={decommissioning}
                onClick={() => onDecommission(server.id)}
              >
                Yes, decommission
              </button>
              <button className="rounded border px-3 py-1" onClick={() => setConfirming(false)}>
                Cancel
              </button>
            </div>
          ) : (
            <button className="rounded border border-red-700 px-3 py-1 text-red-700" onClick={() => setConfirming(true)}>
              Decommission
            </button>
          )}
        </div>
      )}
    </li>
  )
}
