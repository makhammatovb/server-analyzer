import { useState } from 'react'

// The install command carries a single-use token that is shown exactly once.
// Shared by "add server" and "reissue install command".
export default function InstallCommand({ command, token, expiresAt }: { command: string; token: string; expiresAt: string }) {
  const [copied, setCopied] = useState<'yes' | 'failed' | null>(null)
  const [copiedToken, setCopiedToken] = useState<'yes' | 'failed' | null>(null)

  async function copyToken() {
    try {
      await navigator.clipboard.writeText(token)
      setCopiedToken('yes')
    } catch {
      setCopiedToken('failed')
    }
  }

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
        <button className="rounded bg-slate-800 px-3 py-1 text-white" onClick={copy}>Copy command</button>
        {copied === 'yes' && <span role="status" className="text-sm text-green-700">Copied</span>}
        {copied === 'failed' && <span role="status" className="text-sm text-red-700">Copy failed. Select the command and copy it by hand.</span>}
      </div>
      <p className="mb-2 mt-4 text-sm">
        The installer will ask for this enrolment token. Paste it at the prompt (it is not part of the command, so
        it never appears in a process list or in shell history):
      </p>
      <pre data-testid="enrol-token" className="overflow-x-auto rounded bg-slate-900 p-3 text-sm text-slate-100">{token}</pre>
      <div className="mt-2 flex items-center gap-3">
        <button className="rounded bg-slate-800 px-3 py-1 text-white" onClick={copyToken}>Copy token</button>
        {copiedToken === 'yes' && <span role="status" className="text-sm text-green-700">Token copied</span>}
        {copiedToken === 'failed' && <span role="status" className="text-sm text-red-700">Copy failed. Select the token and copy it by hand.</span>}
      </div>
      <p className="mt-3 text-sm">
        This token is single-use and is shown only once; it cannot be retrieved later.
        It expires at <time data-testid="token-expiry" dateTime={expiresAt}>{new Date(expiresAt).toLocaleString()}</time>.
        If you lose it or it expires, reissue the install command from the server list.
      </p>
    </div>
  )
}
