import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type User } from './api/client'

export function useMe() {
  return useQuery({ queryKey: ['me'], queryFn: () => api<User>('/api/me'), staleTime: 60_000 })
}

// Clears the server session and everything cached for this user, then leaves
// for /login whether or not the server call worked.
export function useLogout() {
  const qc = useQueryClient()
  return async () => {
    try {
      await api('/api/logout', { method: 'POST', redirectOn401: false })
    } finally {
      qc.clear()
      window.location.assign('/login')
    }
  }
}
