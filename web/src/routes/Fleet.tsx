import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, type FleetRow } from '../api/client'
import { useMe } from '../auth'
import { offlineFirst } from '../lib'
import ServerCard from '../components/ServerCard'

export const FLEET_POLL_MS = 15_000

export default function Fleet() {
  const qc = useQueryClient()
  const me = useMe()
  const fleet = useQuery({
    queryKey: ['fleet'],
    queryFn: () => api<FleetRow[]>('/api/servers'),
    refetchInterval: FLEET_POLL_MS,
  })
  const decommission = useMutation({
    mutationFn: (id: string) => api<void>(`/api/servers/${id}/decommission`, { method: 'POST' }),
    // A decommissioned server is gone from the API's list; refetch so it is
    // gone from the screen too rather than faking a state the API does not have.
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fleet'] }),
  })
  const isAdmin = me.data?.role === 'admin'

  if (fleet.isPending) return <p>Loading servers…</p>
  if (fleet.isError) return <p role="alert" className="text-red-700">Could not load servers. Retrying every 15 seconds.</p>

  const rows = offlineFirst(fleet.data)
  const offline = rows.filter((r) => !r.online).length

  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Servers</h1>
        <p className="text-sm">
          {rows.length === 0
            ? ''
            : offline === 0
              ? 'All servers online'
              : <span className="font-semibold text-red-700">{offline} offline</span>}
        </p>
      </div>
      {decommission.isError && (
        <p role="alert" className="mb-2 text-sm text-red-700">Decommission failed. The server is still listed.</p>
      )}
      {rows.length === 0 ? (
        <p>
          No servers yet.{isAdmin && <> <Link className="underline" to="/servers/new">Add one</Link>.</>}
        </p>
      ) : (
        <ul className="space-y-2">
          {rows.map((s) => (
            <ServerCard
              key={s.id}
              server={s}
              isAdmin={isAdmin}
              decommissioning={decommission.isPending}
              onDecommission={(id) => decommission.mutate(id)}
            />
          ))}
        </ul>
      )}
    </section>
  )
}
