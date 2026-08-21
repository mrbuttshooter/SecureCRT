import { useEffect, useState } from 'react'
import { ApiError, api, type Credential, type Folder, type Settings, type Trigger } from '../api'
import { TriggerEditor } from './TriggerEditor'

export interface FolderEditorProps {
  folder: Folder | null
  parentId: string
  onSaved: (folder: Folder) => void
  onCancel: () => void
  /** Teams the admin can publish a new top-level folder into. */
  publishTeams?: { id: string; name: string }[]
}

/**
 * FolderEditor names a folder and sets the defaults its contents inherit.
 *
 * Folder defaults are what makes a large device list manageable: an
 * "Edge routers" folder carrying the username and credential means each new
 * router needs only a name and an address. Every field here is optional, and
 * blank means "do not set a default", which is different from setting one to
 * an empty value.
 */
export function FolderEditor(props: FolderEditorProps) {
  const editing = props.folder
  const defaults = editing?.defaults ?? {}

  const [name, setName] = useState(editing?.name ?? '')
  const [username, setUsername] = useState(defaults.username ?? '')
  const [port, setPort] = useState(defaults.port != null ? String(defaults.port) : '')
  const [credentialId, setCredentialId] = useState(defaults.credential_id ?? '')
  const [triggers, setTriggers] = useState<Trigger[]>(defaults.triggers ?? [])
  const [logSession, setLogSession] = useState(defaults.log_session ?? false)
  const [teamId, setTeamId] = useState('')
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

    const settings: Settings = {
      username: username.trim() || null,
      port: port ? Number(port) : null,
      credential_id: credentialId || null,

      // Null rather than [], so "this folder sets no rules" is one state
      // rather than two that have to agree. A connection inside it can still
      // send an explicit empty list to opt out of a parent folder's rules.
      triggers: triggers.length > 0 ? triggers : null,
      log_session: logSession ? true : null,
    }

    const body = editing
      ? { name: name.trim(), defaults: settings }
      : {
          name: name.trim(), parent_id: props.parentId, defaults: settings,
          ...(teamId ? { team_id: teamId } : {}),
        }

    try {
      const saved = editing
        ? await api.patch<Folder>(`/api/tree/folders/${editing.id}`, body)
        : await api.post<Folder>('/api/tree/folders', body)
      props.onSaved(saved)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="card editor" onSubmit={submit}>
      <h2>{editing ? `Defaults for “${editing.name}”` : 'New folder'}</h2>

      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)}
               placeholder="Edge routers" required />
      </label>

      {!editing && props.parentId === '' && (props.publishTeams?.length ?? 0) > 0 && (
        <label>
          Owner
          <select value={teamId} onChange={(e) => setTeamId(e.target.value)}>
            <option value="">My personal tree</option>
            {props.publishTeams!.map((t) => (
              <option key={t.id} value={t.id}>Shared with {t.name}</option>
            ))}
          </select>
        </label>
      )}

      <p className="muted">
        Connections in this folder inherit anything set below, unless they
        specify their own.
      </p>

      <div className="row">
        <label className="grow">
          Default username
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 placeholder="none" />
        </label>
        <label>
          Default port
          <input value={port} onChange={(e) => setPort(e.target.value)}
                 inputMode="numeric" placeholder="none" />
        </label>
      </div>

      <label>
        Default credential
        <select value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
          <option value="">None</option>
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} · {c.kind === 'ssh_key' ? c.key_type || 'key' : c.kind}
            </option>
          ))}
        </select>
      </label>

      <TriggerEditor triggers={triggers} onChange={setTriggers} scope="folder" />

      <label className="check">
        <input type="checkbox" checked={logSession}
               onChange={(e) => setLogSession(e.target.checked)} />
        Record a transcript of every session in this folder
      </label>

      {error && <div className="error">{error}</div>}

      <div className="row">
        <button type="submit" disabled={saving}>
          {saving ? 'Saving…' : editing ? 'Save defaults' : 'Create folder'}
        </button>
        <button type="button" onClick={props.onCancel}>Cancel</button>
      </div>
    </form>
  )
}
