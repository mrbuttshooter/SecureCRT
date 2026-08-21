import { useCallback, useEffect, useState } from 'react'
import { ApiError, api, type Snippet } from '../api'

/**
 * Snippets are the commands people type for the hundredth time.
 *
 * The version of this everybody actually has is a text file beside the
 * terminal, and half of what is in that file is a password. So the placeholder
 * syntax exists to make the other choice easy: write `{{vlan}}`, get asked for
 * it when you send it, and store nothing. Values are never saved — not here,
 * not on the server — which is the difference between a snippet library and a
 * credential store nobody thinks of as one.
 */
export function Snippets() {
  const [items, setItems] = useState<Snippet[]>([])
  const [editing, setEditing] = useState<Snippet | 'new' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setError(null)
    try {
      const body = await api.get<{ snippets: Snippet[] | null }>('/api/snippets')
      setItems(body.snippets ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const remove = async (snippet: Snippet) => {
    if (!window.confirm(`Delete the snippet “${snippet.name}”?`)) return
    try {
      await api.delete(`/api/snippets/${encodeURIComponent(snippet.id)}`)
      setNotice(`Deleted “${snippet.name}”.`)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (editing) {
    return (
      <SnippetEditor
        snippet={editing === 'new' ? null : editing}
        onSaved={async (name) => {
          setEditing(null)
          setNotice(`Saved “${name}”.`)
          await load()
        }}
        onCancel={() => setEditing(null)}
      />
    )
  }

  return (
    <section>
      <div className="spread">
        <h2>Snippets</h2>
        <button className="primary" onClick={() => setEditing('new')}>New snippet</button>
      </div>

      <p className="muted">
        Send one to a terminal from the Snippets button on any open session.
        With a broadcast group active it goes to every terminal in the group,
        which is what makes the same four commands across eight switches one
        action rather than thirty-two.
      </p>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      {loading ? (
        <p className="muted">Loading…</p>
      ) : items.length === 0 ? (
        <div className="card">
          <p>No snippets yet.</p>
          <p className="muted">
            A snippet is a command you keep typing. Put <code>{'{{name}}'}</code>
            {' '}where the value changes, and you are asked for it when you send
            it — so nothing that changes has to be stored.
          </p>
        </div>
      ) : (
        <table className="grid" data-testid="snippet-list">
          <thead>
            <tr><th>Name</th><th>Command</th><th>Variables</th><th /></tr>
          </thead>
          <tbody>
            {items.map((snippet) => (
              <tr key={snippet.id}>
                <td>
                  {snippet.name}
                  {snippet.description && (
                    <><br /><span className="muted">{snippet.description}</span></>
                  )}
                </td>
                <td><pre className="snippet-body">{snippet.body}</pre></td>
                <td>
                  {snippet.parameters.length === 0
                    ? <span className="muted">{'\u2014'}</span>
                    : snippet.parameters.map((p) => <code key={p}>{p} </code>)}
                </td>
                <td className="nowrap actions-cell">
                  <button onClick={() => setEditing(snippet)}>Edit</button>
                  <button className="link danger" onClick={() => void remove(snippet)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function SnippetEditor(props: {
  snippet: Snippet | null
  onSaved: (name: string) => void
  onCancel: () => void
}) {
  const editing = props.snippet
  const [name, setName] = useState(editing?.name ?? '')
  const [description, setDescription] = useState(editing?.description ?? '')
  const [body, setBody] = useState(editing?.body ?? '')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Shown as it is typed rather than after saving, so the placeholder syntax
  // is discoverable by using it: type {{vlan}} and watch "vlan" appear.
  const parameters = Array.from(
    new Set(Array.from(body.matchAll(/\{\{([A-Za-z0-9_-]{1,40})\}\}/g), (m) => m[1]!)),
  )

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setSaving(true)
    const payload = { name: name.trim(), description: description.trim(), body }
    try {
      if (editing) await api.patch(`/api/snippets/${encodeURIComponent(editing.id)}`, payload)
      else await api.post('/api/snippets', payload)
      props.onSaved(payload.name)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="card editor" onSubmit={submit}>
      <h2>{editing ? `Edit “${editing.name}”` : 'New snippet'}</h2>

      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)}
               placeholder="show interface status" required />
      </label>

      <label>
        What it does
        <input value={description} onChange={(e) => setDescription(e.target.value)}
               placeholder="optional" />
      </label>

      <label>
        Command
        <textarea
          rows={6}
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder={'interface {{port}}\ndescription {{note}}\n'}
          required
        />
      </label>

      <p className="muted">
        Sent exactly as written, newlines and all — so a line that should be
        entered needs a newline after it. Use <code>{'{{name}}'}</code> where a
        value changes; you are asked for it each time.
      </p>

      <p className="warn">
        Never put a password in a snippet. Snippets are stored as written and
        are not part of the vault; a password belongs in Credentials, where it
        is encrypted, or in a watch rule as <code>%PASSWORD%</code>.
      </p>

      {parameters.length > 0 && (
        <p className="muted">
          This snippet will ask for: {parameters.map((p) => <code key={p}>{p} </code>)}
        </p>
      )}

      {error && <div className="error">{error}</div>}

      <div className="row">
        <button type="submit" disabled={saving}>
          {saving ? 'Saving…' : editing ? 'Save changes' : 'Create snippet'}
        </button>
        <button type="button" onClick={props.onCancel}>Cancel</button>
      </div>
    </form>
  )
}
