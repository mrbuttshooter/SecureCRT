import { useEffect, useState } from 'react'
import { ApiError, api, type Credential, type Folder } from '../api'

/**
 * FolderCredentialPicker is the member-side half of the shared tree: a shared
 * folder says where to connect, and this is where each engineer says with
 * which of their own credentials. The choice is remembered per folder and
 * covers everything inside it, so a rack is one decision.
 */
export function FolderCredentialPicker({ folder, onClose }: {
  folder: Folder
  onClose: () => void
}) {
  const [credentials, setCredentials] = useState<Credential[] | null>(null)
  const [chosen, setChosen] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void api
      .get<{ credentials: Credential[] | null }>('/api/credentials')
      .then((r) => {
        const list = r.credentials ?? []
        setCredentials(list)
        if (list.length > 0) setChosen(list[0]!.id)
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err))
        setCredentials([])
      })
  }, [])

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.post(`/api/tree/folders/${folder.id}/credential`, { credential_id: chosen })
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="editor-overlay">
      <div className="card editor">
        <h2>Your credential for “{folder.name}”</h2>
        <p className="muted">
          This shared folder is published by an administrator. Choose which of
          your own keys or passwords opens the devices inside it — your choice,
          remembered only for you, covering the whole folder.
        </p>

        {error && <div className="error">{error}</div>}

        {credentials?.length === 0 && (
          <p>You have no credentials yet. Add one under Credentials first.</p>
        )}

        {credentials && credentials.length > 0 && (
          <label>
            <span>Credential</span>
            <select value={chosen} onChange={(e) => setChosen(e.target.value)}>
              {credentials.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}{c.username ? ` (${c.username})` : ''}
                </option>
              ))}
            </select>
          </label>
        )}

        <div className="row">
          <button className="primary" disabled={busy || !chosen} onClick={() => void save()}>
            {busy ? 'Saving…' : 'Use this credential'}
          </button>
          <button onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  )
}
