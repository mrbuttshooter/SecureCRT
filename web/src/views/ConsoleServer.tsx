import { useEffect, useState } from 'react'
import {
  ApiError, api,
  type ConsolePlan, type ConsoleProfile, type Credential,
} from '../api'

export interface ConsoleServerProps {
  /** Where the generated lines go. */
  folderId: string
  onCreated: () => void
  onCancel: () => void
}

/**
 * ConsoleServer turns one appliance into a folder of lines.
 *
 * Plan then apply, like every import here: forty-eight connections generated
 * from a base port that was right for the last rack is a mistake to catch on
 * screen rather than six weeks later in an outage. The plan shows every
 * resulting port, and nothing is written until it has been looked at.
 */
export function ConsoleServer(props: ConsoleServerProps) {
  const [profiles, setProfiles] = useState<ConsoleProfile[]>([])
  const [profileId, setProfileId] = useState('opengear')
  const [hostname, setHostname] = useState('')
  const [protocol, setProtocol] = useState<'ssh' | 'telnet'>('ssh')
  const [basePort, setBasePort] = useState('')
  const [lines, setLines] = useState('48')
  const [namePattern, setNamePattern] = useState('')
  const [username, setUsername] = useState('')
  const [credentialId, setCredentialId] = useState('')

  const [credentials, setCredentials] = useState<Credential[]>([])
  const [plan, setPlan] = useState<ConsolePlan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void api
      .get<{ profiles: ConsoleProfile[]; default_name_pattern: string }>(
        '/api/consoles/profiles',
      )
      .then((r) => {
        setProfiles(r.profiles ?? [])
        setNamePattern((current) => current || r.default_name_pattern)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))

    void api
      .get<{ credentials: Credential[] }>('/api/credentials')
      .then((r) => setCredentials(r.credentials ?? []))
      .catch(() => setCredentials([]))
  }, [])

  const chosen = profiles.find((p) => p.id === profileId)

  const body = () => ({
    profile_id: profileId,
    hostname: hostname.trim(),
    protocol,
    base_port: basePort ? Number(basePort) : 0,
    lines: lines ? Number(lines) : 0,
    name_pattern: namePattern,
    username: username.trim(),
    credential_id: credentialId,
    folder_id: props.folderId,
  })

  const preview = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      setPlan(await api.post<ConsolePlan>('/api/consoles/plan', body()))
    } catch (err) {
      setPlan(null)
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const apply = async () => {
    setError(null)
    setBusy(true)
    try {
      await api.post('/api/consoles/apply', body())
      props.onCreated()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card editor" onSubmit={preview}>
      <h2>Add a console server</h2>
      <p className="muted">
        One appliance becomes one connection per line. This is telnet or SSH
        to a port derived from the line number — no new protocol, just the
        arithmetic done once instead of forty-eight times.
      </p>

      <label>
        Appliance
        <select value={profileId} onChange={(e) => { setProfileId(e.target.value); setPlan(null) }}>
          {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </label>
      {chosen && <p className="muted">{chosen.note}</p>}

      <div className="row">
        <label className="grow">
          Address
          <input value={hostname} onChange={(e) => { setHostname(e.target.value); setPlan(null) }}
                 placeholder="console-01.example.com" required />
        </label>
        <label>
          Reached over
          <select value={protocol}
                  onChange={(e) => { setProtocol(e.target.value as 'ssh' | 'telnet'); setPlan(null) }}>
            <option value="ssh">SSH</option>
            <option value="telnet">Telnet</option>
          </select>
        </label>
      </div>

      <div className="row">
        <label>
          Lines
          <input value={lines} onChange={(e) => { setLines(e.target.value); setPlan(null) }}
                 inputMode="numeric" required />
        </label>
        <label>
          Base port
          <input value={basePort} onChange={(e) => { setBasePort(e.target.value); setPlan(null) }}
                 inputMode="numeric"
                 placeholder={chosen
                   ? String(protocol === 'telnet' ? chosen.telnet_base : chosen.ssh_base)
                   : ''} />
        </label>
        <label className="grow">
          Name each line
          <input value={namePattern} onChange={(e) => { setNamePattern(e.target.value); setPlan(null) }}
                 placeholder="%h line %n" />
        </label>
      </div>
      <p className="muted">
        These port numbers are what the appliance ships with and every one of
        them is configurable, so check one line against the device before
        creating fifty. <code>%h</code> is the address and <code>%n</code> the
        line number, padded so the tree sorts like the rack.
      </p>

      <div className="row">
        <label className="grow">
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 placeholder="the appliance's login" />
        </label>
        <label className="grow">
          Credential
          <select value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
            <option value="">None — each line will ask</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} · {c.kind === 'ssh_key' ? c.key_type || 'key' : c.kind}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && <div className="error">{error}</div>}

      {plan && (
        <>
          {plan.warnings?.map((warning) => (
            <div className="warn" key={warning}>{warning}</div>
          ))}

          <p className="muted">
            {plan.lines.length} connections would be created. Nothing has been
            written yet.
          </p>

          <div className="plan-lines">
            <table className="grid">
              <thead>
                <tr><th>Line</th><th>Name</th><th>Port</th></tr>
              </thead>
              <tbody>
                {plan.lines.map((line) => (
                  <tr key={line.line}>
                    <td>{line.line}</td>
                    <td>{line.name}</td>
                    <td><code>{plan.hostname}:{line.port}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <div className="row">
        <button type="submit" disabled={busy}>
          {busy ? 'Working…' : plan ? 'Update the preview' : 'Preview'}
        </button>
        {plan && (
          <button type="button" className="primary" disabled={busy} onClick={() => void apply()}>
            Create {plan.lines.length} connections
          </button>
        )}
        <button type="button" onClick={props.onCancel}>Cancel</button>
      </div>
    </form>
  )
}
