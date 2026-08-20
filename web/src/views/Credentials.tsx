import { useCallback, useEffect, useState } from 'react'
import { ApiError, api, type Credential } from '../api'

type Mode = 'list' | 'generate' | 'import' | 'password'

export function Credentials() {
  const [items, setItems] = useState<Credential[]>([])
  const [mode, setMode] = useState<Mode>('list')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setError(null)
    try {
      const body = await api.get<{ credentials: Credential[] | null }>('/api/credentials')
      setItems(body.credentials ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const afterChange = async (message?: string) => {
    setMode('list')
    setNotice(message ?? null)
    await load()
  }

  const remove = async (c: Credential) => {
    // A stored key is unrecoverable once deleted, so the confirmation names
    // what is going and does not rely on the user remembering which row they
    // clicked.
    if (!window.confirm(`Delete "${c.name}"? This cannot be undone.`)) return
    try {
      await api.delete(`/api/credentials/${encodeURIComponent(c.id)}`)
      await afterChange(`Deleted "${c.name}".`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (mode === 'generate') return <GenerateKey onDone={afterChange} onCancel={() => setMode('list')} />
  if (mode === 'import') return <ImportKey onDone={afterChange} onCancel={() => setMode('list')} />
  if (mode === 'password') return <AddPassword onDone={afterChange} onCancel={() => setMode('list')} />

  return (
    <section>
      <div className="spread">
        <h2>Credentials</h2>
        <div className="row">
          <button className="primary" onClick={() => setMode('generate')}>Generate SSH key</button>
          <button onClick={() => setMode('import')}>Import key</button>
          <button onClick={() => setMode('password')}>Add password</button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      {loading ? (
        <p className="muted">Loading…</p>
      ) : items.length === 0 ? (
        <div className="card">
          <p>No credentials yet.</p>
          <p className="muted">
            Generate a key here and add its public half to the hosts you want to
            reach. The private half stays encrypted on the server and is never
            sent to your browser.
          </p>
        </div>
      ) : (
        <ul className="plain card">
          {items.map((c) => (
            <li key={c.id}>
              <div className="spread">
                <div>
                  <strong>{c.name}</strong>{' '}
                  <span className="tag">{c.kind.replace('_', ' ')}</span>
                  {c.key_type && <> <span className="tag">{c.key_type}</span></>}
                  {c.server_unlockable && <> <span className="tag">server-unlockable</span></>}
                  {c.username && <div className="muted">username: {c.username}</div>}
                  {c.fingerprint && <div className="mono">{c.fingerprint}</div>}
                  <div className="muted">
                    added {new Date(c.created_at).toLocaleDateString()}
                    {c.last_used_at && <> · last used {new Date(c.last_used_at).toLocaleDateString()}</>}
                  </div>
                </div>
                <button className="danger" onClick={() => void remove(c)}>Delete</button>
              </div>
              {c.public_key && (
                <details>
                  <summary className="muted">Public key</summary>
                  <p className="mono">{c.public_key}</p>
                </details>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function GenerateKey({ onDone, onCancel }: {
  onDone: (message?: string) => Promise<void>
  onCancel: () => void
}) {
  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [keyType, setKeyType] = useState('ed25519')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<Credential | null>(null)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      setCreated(await api.post<Credential>('/api/credentials/generate', {
        name, username, key_type: keyType,
      }))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  if (created) {
    return (
      <section>
        <h2>Key created</h2>
        <div className="notice">
          The private key is stored encrypted and never leaves the server.
          Add the public key below to the hosts you want to reach.
        </div>
        <div className="card">
          <p className="muted">Public key — paste this into <code>~/.ssh/authorized_keys</code></p>
          <p className="mono">{created.public_key}</p>
          <hr />
          <p className="muted">Fingerprint — check this matches what the host reports</p>
          <p className="mono">{created.fingerprint}</p>
        </div>
        <button className="primary" onClick={() => void onDone(`Created "${created.name}".`)}>
          Done
        </button>
      </section>
    )
  }

  return (
    <section>
      <h2>Generate an SSH key</h2>
      {error && <div className="error">{error}</div>}
      <form className="card" onSubmit={(e) => void submit(e)}>
        <label>
          <span>Name</span>
          <input value={name} required autoFocus placeholder="Production jump host"
                 onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          <span>Username on the remote host (optional)</span>
          <input value={username} placeholder="root"
                 onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          <span>Algorithm</span>
          <select value={keyType} onChange={(e) => setKeyType(e.target.value)}>
            <option value="ed25519">Ed25519 — recommended</option>
            <option value="rsa-4096">RSA 4096 — for older equipment</option>
            <option value="ecdsa-p256">ECDSA P-256</option>
            <option value="ecdsa-p384">ECDSA P-384</option>
          </select>
        </label>
        <p className="muted">
          Ed25519 unless something you connect to is too old to accept it.
        </p>
        <div className="row">
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Generating…' : 'Generate'}
          </button>
          <button type="button" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </section>
  )
}

function ImportKey({ onDone, onCancel }: {
  onDone: (message?: string) => Promise<void>
  onCancel: () => void
}) {
  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [needsPassphrase, setNeedsPassphrase] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const created = await api.post<Credential>('/api/credentials/import', {
        name, username, private_key: privateKey, passphrase,
      })
      await onDone(created.notice ?? `Imported "${created.name}".`)
    } catch (err) {
      // The server distinguishes "this key needs a passphrase" from other
      // failures precisely so the form can ask for one instead of showing a
      // dead end.
      if (err instanceof ApiError && err.code === 'key_encrypted') {
        setNeedsPassphrase(true)
        setError('This key is protected by a passphrase. Enter it below.')
      } else {
        setError(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <h2>Import an existing key</h2>
      {error && <div className="error">{error}</div>}
      <form className="card" onSubmit={(e) => void submit(e)}>
        <label>
          <span>Name</span>
          <input value={name} required autoFocus onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          <span>Username on the remote host (optional)</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          <span>Private key</span>
          <textarea value={privateKey} required spellCheck={false}
                    placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----'}
                    onChange={(e) => setPrivateKey(e.target.value)} />
        </label>
        {needsPassphrase && (
          <label>
            <span>Key passphrase</span>
            <input type="password" value={passphrase} autoFocus autoComplete="off"
                   onChange={(e) => setPassphrase(e.target.value)} />
          </label>
        )}
        <p className="muted">
          Paste the whole file, including its BEGIN and END lines. If the key has
          its own passphrase it will be removed on import — your vault protects
          it from then on, so you will not be asked for it again.
        </p>
        <div className="row">
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Importing…' : 'Import'}
          </button>
          <button type="button" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </section>
  )
}

function AddPassword({ onDone, onCancel }: {
  onDone: (message?: string) => Promise<void>
  onCancel: () => void
}) {
  const [name, setName] = useState('')
  const [kind, setKind] = useState('password')
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const created = await api.post<Credential>('/api/credentials', {
        name, kind, username, secret,
      })
      await onDone(`Saved "${created.name}".`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <h2>Add a password</h2>
      {error && <div className="error">{error}</div>}
      <form className="card" onSubmit={(e) => void submit(e)}>
        <label>
          <span>Name</span>
          <input value={name} required autoFocus placeholder="Core switch"
                 onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          <span>Type</span>
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="password">Password</option>
            <option value="enable_secret">Enable secret</option>
            <option value="passphrase">Passphrase</option>
          </select>
        </label>
        <label>
          <span>Username (optional)</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          <span>Secret</span>
          <input type="password" value={secret} required autoComplete="off"
                 onChange={(e) => setSecret(e.target.value)} />
        </label>
        <div className="row">
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
          <button type="button" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </section>
  )
}
