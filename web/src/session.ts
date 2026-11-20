import type { QueryClient } from '@tanstack/react-query'
import { setUnauthorizedHandler } from './api/client'

// A 401 on any request means the session is gone: drop everything cached for
// the old user and go to /login. Installed once, from main.tsx.
export function installSessionExpiry(
  qc: QueryClient,
  navigate: (path: string) => void = (p) => window.location.assign(p),
) {
  setUnauthorizedHandler(() => {
    qc.clear()
    if (window.location.pathname !== '/login') navigate('/login')
  })
}
