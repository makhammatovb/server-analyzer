export const admin = { id: 'u1', username: 'root', role: 'admin', is_active: true }
export const plainUser = { id: 'u2', username: 'viewer', role: 'user', is_active: true }

export function row(over: Record<string, unknown> = {}) {
  return {
    id: 's1',
    name: 'web-1',
    note: '',
    created_at: '2026-11-01T00:00:00Z',
    last_seen_at: new Date(Date.now() - 5_000).toISOString(),
    agent_version: '0.1.0',
    online: true,
    cert_not_after: new Date(Date.now() + 60 * 86_400_000).toISOString(),
    ...over,
  }
}
