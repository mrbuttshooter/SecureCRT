import { useEffect, useRef, useState } from 'react'
import { ApiError, api, type Credential, type SavedSession, type Tree } from '../api'

/** The folder ad-hoc connections are filed under, created on first use. */
const QUICK_FOLDER = 'Quick connect'

export interface QuickConnectProps {
  tree: Tree
  /** Focus the input when this becomes true (the Ctrl+Shift+Q path). */
  focusSignal: number
  onConnected: (session: SavedSession) => void
  onTreeChanged: () => void
}

/**
 * QuickConnect is the SecureCRT "Enter host" bar: type `admin@10.0.0.1:2222`,
 * press Enter, get a terminal.
 *
 * The wire protocol only dials saved connections — deliberately, so host-key
 * verification, recording policy and the audit trail all stay on one path —
 * so this saves first and connects immediately, filing the record under a
 * "Quick connect" folder where it doubles as connection history. Deleting
 * the folder is how you clear that history.
 */
export function QuickConnect(props: QuickConnectProps) {
  const [value, setValue] = useState('')
  const [credentialId, setCredentialId] = useState('')
  const [credentials, setCredentials] = useState<Credential[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    void api
      .get<{ credentials: Credential[] | null }>('/api/credentials')
      .then((r) => {
        const list = r.credentials ?? []
        setCredentials(list)
        // Default to the last quick-connect choice, else the first credential.
        const last = window.localStorage.getItem('bkd.quick.credential')
        if (last && list.some((c) => c.id === last)) setCredentialId(last)
        else if (list.length > 0) setCredentialId(list[0]!.id)
      })
      .catch(() => setCredentials([]))
  }, [])

  useEffect(() => {
    if (props.focusSignal > 0) input.current?.focus()
  }, [props.focusSignal])

  const connect = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)

    // user@host:port, every part but the host optional. IPv6 literals go in
    // brackets, the way OpenSSH writes them.
    const m = value.trim().match(
      /^(?:(?<user>[^@\s]+)@)?(?:\[(?<v6>[0-9a-fA-F:]+)\]|(?<host>[^@\s:\[\]]+))(?::(?<port>\d{1,5}))?$/,
    )
    const host = m?.groups?.v6 ?? m?.groups?.host
    if (!m || !host) {
      setError('Enter a host: 10.0.0.1, admin@switch, or admin@10.0.0.1:2222.')
      return
    }

    setBusy(true)
    try {
      let folder = props.tree.folders.find(
        (f) => f.parent_id === '' && f.name === QUICK_FOLDER,
      )
      if (!folder) {
        folder = await api.post<typeof folder & object>('/api/tree/folders', {
          parent_id: '', name: QUICK_FOLDER,
        })
        props.onTreeChanged()
      }

      const session = await api.post<SavedSession>('/api/tree/sessions', {
        folder_id: folder!.id,
        name: m.groups?.user ? `${m.groups.user}@${host}` : host,
        protocol: 'ssh',
        hostname: host,
        port: m.groups?.port ? Number(m.groups.port) : 0,
        username: m.groups?.user ?? '',
        credential_id: credentialId,
        jump_chain: [],
        settings: {},
      })
      window.localStorage.setItem('bkd.quick.credential', credentialId)
      props.onTreeChanged()
      props.onConnected(session)
      setValue('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="quick-connect" onSubmit={(e) => void connect(e)}>
      <input
        ref={input}
        aria-label="Quick connect"
        placeholder={'user@host \u2014 press Enter to connect'}
        value={value}
        disabled={busy}
        onChange={(e) => setValue(e.target.value)}
      />
      {credentials.length > 0 && (
        <select
          aria-label="Credential for quick connect"
          value={credentialId}
          onChange={(e) => setCredentialId(e.target.value)}
        >
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>
      )}
      <button type="submit" disabled={busy || !value.trim()}>
        {busy ? 'Connecting\u2026' : 'Connect'}
      </button>
      {error && <p className="error quick-error">{error}</p>}
    </form>
  )
}
