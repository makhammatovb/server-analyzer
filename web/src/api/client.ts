// The one place that talks to the backend. The session is an HttpOnly cookie:
// this code never reads, stores or forwards it, it only asks the browser to
// send it (credentials: 'include').

export class ApiError extends Error {
  readonly status: number
  constructor(status: number) {
    super(`request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
  }
}

// The default is loud on purpose: if main.tsx never installs the real handler, a
// 401 must announce that wiring bug rather than look like a network failure.
let onUnauthorized: () => void = () => {
  console.error('api client: a 401 arrived but the session-expiry handler was never installed (see installSessionExpiry)')
}

// A 401 on any request means the session is gone. main.tsx installs the handler
// that clears client state and goes to /login; screens do not handle it.
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

export interface RequestOptions {
  method?: string
  body?: unknown
  // Login is the one request whose 401 means "bad credentials", not "session lost".
  redirectOn401?: boolean
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {}
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'

  const res = await fetch(new URL(path, window.location.origin), {
    method: opts.method ?? 'GET',
    credentials: 'include',
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  })

  if (res.status === 401 && opts.redirectOn401 !== false) onUnauthorized()
  if (!res.ok) throw new ApiError(res.status)
  if (res.status === 204) return undefined as T
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

export interface User {
  id: string
  username: string
  role: 'admin' | 'user'
  is_active: boolean
  created_at?: string
}

export interface Server {
  id: string
  name: string
  note: string
  created_at: string
}

export interface FleetRow extends Server {
  last_seen_at: string | null
  agent_version: string
  online: boolean
  cert_not_after: string | null
}

export interface CreatedServer {
  server: Server
  install_command: string
  token_expires_at: string
}
