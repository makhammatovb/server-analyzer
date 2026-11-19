import { useState } from 'react'

// The install command carries a single-use token that is shown exactly once.
// Shared by "add server" and "reissue install command".
export default function InstallCommand({ command, expiresAt }: { command: string; expiresAt: string }) {
  const [copied, setCopied] = useState<'yes' | 'failed' | null>(null)

  async function copy() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied('yes')
    } catch {
      setCopied('failed')
    }
  }

  return (
    <div>
      <p className="mb-2 text-sm">Run this command as root on the server:</p>
      <pre data-testid="install-command" className="overflow-x-auto rounded bg-slate-900 p-3 text-sm text-slate-100">
        {command}
      </pre>
      <div className="mt-2 flex items-center gap-3">
        <button className="rounded bg-slate-800 px-3 py-1 text-white" onClick={copy}>Copy</button>
        {copied === 'yes' && <span role="status" className="text-sm text-green-700">Copied</span>}
        {copied === 'failed' && <span role="status" className="text-sm text-red-700">Copy failed. Select the command and copy it by hand.</span>}
      </div>
      <p className="mt-3 text-sm">
        This command contains a single-use token and is shown only once; it cannot be retrieved later.
        It expires at <time data-testid="token-expiry" dateTime={expiresAt}>{new Date(expiresAt).toLocaleString()}</time>.
        If you lose it or it expires, reissue the install command from the server list.
      </p>
    </div>
  )
}
