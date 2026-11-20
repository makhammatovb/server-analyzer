import { useLogout } from '../auth'

export default function Pending() {
  const logout = useLogout()
  return (
    <main className="mx-auto mt-24 max-w-md p-4">
      <h1 className="mb-2 text-xl font-semibold">Waiting for activation</h1>
      <p>Your account is not active. An administrator must activate it before you can use FleetGuard.</p>
      <button className="mt-4 underline" onClick={logout}>Sign out</button>
    </main>
  )
}
