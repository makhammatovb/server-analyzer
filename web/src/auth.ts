import { useQuery } from '@tanstack/react-query'
import { api, type User } from './api/client'

export function useMe() {
  return useQuery({ queryKey: ['me'], queryFn: () => api<User>('/api/me'), staleTime: 60_000 })
}
