import type { FleetRow } from './api/client'

// Offline servers first: the list exists to answer "is anything wrong?".
// Array.prototype.sort is stable, so each group keeps the API's (name) order.
export function offlineFirst(rows: FleetRow[]): FleetRow[] {
  return [...rows].sort((a, b) => Number(a.online) - Number(b.online))
}

const UNITS: [string, number][] = [
  ['day', 86_400_000],
  ['hour', 3_600_000],
  ['minute', 60_000],
]

export function relativeTime(iso: string | null, now = Date.now()): string {
  if (!iso) return 'never'
  const ms = now - new Date(iso).getTime()
  if (ms < 60_000) return 'just now'
  for (const [unit, size] of UNITS) {
    if (ms >= size) {
      const n = Math.floor(ms / size)
      return `${n} ${unit}${n === 1 ? '' : 's'} ago`
    }
  }
  return 'just now'
}

export function daysUntil(iso: string, now = Date.now()): number {
  return Math.floor((new Date(iso).getTime() - now) / 86_400_000)
}
