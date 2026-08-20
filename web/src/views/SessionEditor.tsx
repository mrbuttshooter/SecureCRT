import { useEffect, useState } from 'react'
import { ApiError, api, type Credential, type SavedSession, type Settings } from '../api'

export interface SessionEditorProps {
  /** The connection being edited, or null when creating one. */
  session: SavedSession | null
  folderId: string
  onSaved: (session: SavedSession) => void
  onCancel: () => void
}

const PROTOCOLS = [
  { value: 'ssh', label: 'SSH' },
  { value: 'telnet', label: 'Telnet' },
  { value: 'serial', label: 'Serial' },
] as const

/**
 * SessionEditor creates or edits one saved connection.
 *
 * Blank fields mean "inherit from the folder" rather than "empty", which is
 * the whole point of folder defaults: setting a username once on a folder of
 * three hundred switches should not have to be repeated on each. The form
 * says so next to each inheritable field instead of leaving the user to
 * discover it.
 */
export function SessionEditor(props: SessionEditorProps) {
  const editing = props.session

  const [name, setName] = useState(editing?.name ?? '')
  const [hostname, setHostname] = useState(editing?.hostname ?? '')
  const [protocol, setProtocol] = useState<'ssh' | 'telnet' | 'serial'>(editing?.protocol ?? 'ssh')
  const [port, setPort] = useState(editing ? String(editing.port) : '')
  const [username, setUsername] = useState(editing?.username ?? '')
  const [credentialId, setCredentialId] = useState(editing?.credential_id ?? '')
  const [keepalive, setKeepalive] = useState(
    editing?.settings?.keepalive_seconds != null ? String(editing.settings.keepalive_seconds) : '',
  )
  const [scrollback, setScrollback] = useState(
    editing?.settings?.scrollback != null ? String(editing.settings.scrollback) : '',
  )

  const [credentials, setCredentials] = useState<Credential[]>([])
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    void api
      .get<{ credentials: Credential[] }>('/api/credentials')
      .then((r) => setCredentials(r.credentials ?? []))
      .catch(() => setCredentials([]))
  }, [])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setSaving(true)

    // A blank optional field is sent as null, which the server reads as
    // "inherit". Sending "" would instead pin it to empty, which is a
    // different and almost never intended thing.
    const settings: Settings = {
      keepalive_seconds: keepalive ? Number(keepalive) : null,
      scrollback: scrollback ? Number(scrollback) : null,
    }

    const body = {
      folder_id: props.folderId,
      name: name.trim(),
      protocol,
      hostname: hostname.trim(),
      port: port ? Number(port) : 0,
      username: username.trim(),
      credential_id: credentialId,
      settings,
    }

    try {
      const saved = editing
        ? await api.patch<SavedSession>(`/api/tree/sessions/${editing.id}`, body)
        : await api.post<SavedSession>('/api/tree/sessions', body)
      props.onSaved(saved)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="card editor" onSubmit={submit}>
      <h2>{editing ? 'Edit connection' : 'New connection'}</h2>

      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)}
               placeholder="core-sw-01" required />
      </label>

      <div className="row">
        <label className="grow">
          Hostname or address
          <input value={hostname} onChange={(e) => setHostname(e.target.value)}
                 placeholder="10.0.0.1" required />
        </label>

        <label>
          Protocol
          <select value={protocol}
                  onChange={(e) => setProtocol(e.target.value as typeof protocol)}>
            {PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
        </label>
      </div>

      <div className="row">
        <label>
          Port
          <input value={port} onChange={(e) => setPort(e.target.value)}
                 inputMode="numeric" placeholder="inherited" />
        </label>

        <label className="grow">
          Username on the remote host
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 placeholder="inherited from the folder" />
        </label>
      </div>

      <label>
        Credential
        <select value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
          <option value="">Inherited from the folder</option>
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} · {c.kind === 'ssh_key' ? c.key_type || 'key' : c.kind}
            </option>
          ))}
        </select>
      </label>

      <details>
        <summary>Advanced</summary>
        <div className="row">
          <label>
            Keepalive (seconds)
            <input value={keepalive} onChange={(e) => setKeepalive(e.target.value)}
                   inputMode="numeric" placeholder="inherited" />
          </label>
          <label>
            Scrollback (lines)
            <input value={scrollback} onChange={(e) => setScrollback(e.target.value)}
                   inputMode="numeric" placeholder="inherited" />
          </label>
        </div>
        <p className="muted">
          Blank means the value is inherited from the folder this connection
          lives in, and follows it if the folder changes.
        </p>
      </details>

      {error && <div className="error">{error}</div>}

      <div className="row">
        <button type="submit" disabled={saving}>
          {saving ? 'Saving…' : editing ? 'Save changes' : 'Create connection'}
        </button>
        <button type="button" onClick={props.onCancel}>Cancel</button>
      </div>
    </form>
  )
}
