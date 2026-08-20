import { useEffect, useState } from 'react'
import {
  ApiError, api,
  type Credential, type LogonStep, type SavedSession, type Settings, type Tree,
} from '../api'

export interface SessionEditorProps {
  /** The connection being edited, or null when creating one. */
  session: SavedSession | null
  folderId: string
  onSaved: (session: SavedSession) => void
  onCancel: () => void
}

// The rates termios can be told about, which is what the server accepts.
const BAUD_RATES = [
  300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600,
] as const

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
  // Blank means inherited, and zero is how the server says the same thing —
  // so a saved connection with no port of its own opens with an empty field
  // rather than the literal "0".
  const [port, setPort] = useState(editing?.port ? String(editing.port) : '')
  const [username, setUsername] = useState(editing?.username ?? '')
  const [credentialId, setCredentialId] = useState(editing?.credential_id ?? '')
  const [keepalive, setKeepalive] = useState(
    editing?.settings?.keepalive_seconds != null ? String(editing.settings.keepalive_seconds) : '',
  )
  const [scrollback, setScrollback] = useState(
    editing?.settings?.scrollback != null ? String(editing.settings.scrollback) : '',
  )

  // The jump chain has been stored, imported, exported and dialled since
  // Phase 5a, and until now there has been no way to see or set it. An
  // imported SecureCRT tree arrives with firewalls already resolved, so this
  // form is often the first place a person finds out a route exists.
  const [jumpChain, setJumpChain] = useState<string[]>(editing?.jump_chain ?? [])

  const [agentKeys, setAgentKeys] = useState<string[]>(
    editing?.settings?.agent_forward_credentials ?? [],
  )

  const [logonSteps, setLogonSteps] = useState<LogonStep[]>(
    editing?.settings?.logon_steps ?? [],
  )

  const [baud, setBaud] = useState(
    editing?.settings?.serial_baud != null ? String(editing.settings.serial_baud) : '',
  )
  const [parity, setParity] = useState(editing?.settings?.serial_parity ?? '')
  const [flow, setFlow] = useState(editing?.settings?.serial_flow ?? '')

  const [credentials, setCredentials] = useState<Credential[]>([])
  const [hosts, setHosts] = useState<SavedSession[]>([])
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    void api
      .get<{ credentials: Credential[] }>('/api/credentials')
      .then((r) => setCredentials(r.credentials ?? []))
      .catch(() => setCredentials([]))
  }, [])

  useEffect(() => {
    void api
      .get<Tree>('/api/tree')
      .then((r) => setHosts(r.sessions ?? []))
      .catch(() => setHosts([]))
  }, [])

  // A connection cannot be its own jump host, so it is not offered as one.
  // The server refuses it too — this only keeps the list honest.
  const candidates = hosts.filter((h) => h.id !== editing?.id && h.protocol === 'ssh')
  const keyCredentials = credentials.filter((c) => c.kind === 'ssh_key')

  const isSerial = protocol === 'serial'
  const isSSH = protocol === 'ssh'

  const setStep = (index: number, patch: Partial<LogonStep>) => {
    setLogonSteps((prev) =>
      prev.map((step, i) => (i === index ? { ...step, ...patch } : step)),
    )
  }

  const setHop = (index: number, id: string) => {
    setJumpChain((prev) => {
      const next = [...prev]
      if (id === '') next.splice(index, 1)
      else next[index] = id
      return next
    })
  }

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
      // An empty list is sent as null rather than [], so "no agent" is one
      // state on the wire rather than two that have to agree.
      agent_forward_credentials: agentKeys.length > 0 ? agentKeys : null,

      // Logon steps are the opposite: null and empty mean different things.
      // Null is "say nothing", which falls back to the default sequence when
      // a password is stored; empty is "send nothing", which is how one
      // connection inside a folder opts out of the folder's sequence.
      logon_steps: logonSteps.length > 0 ? logonSteps : editing?.settings?.logon_steps ?? null,

      serial_baud: isSerial && baud ? Number(baud) : null,
      serial_parity: isSerial && parity ? parity : null,
      serial_flow: isSerial && flow ? flow : null,
    }

    const body = {
      folder_id: props.folderId,
      name: name.trim(),
      protocol,
      hostname: hostname.trim(),
      port: port ? Number(port) : 0,
      username: username.trim(),
      credential_id: credentialId,
      jump_chain: jumpChain.filter(Boolean),
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
          {/*
            A serial line addresses a device rather than a host, which is the
            one place in this system where "no hostname" is correct. The field
            is the same column underneath; only what it means changes.
          */}
          {isSerial ? 'Serial device' : 'Hostname or address'}
          <input value={hostname} onChange={(e) => setHostname(e.target.value)}
                 placeholder={isSerial ? '/dev/ttyUSB0' : '10.0.0.1'} required />
        </label>

        <label>
          Protocol
          <select value={protocol}
                  onChange={(e) => setProtocol(e.target.value as typeof protocol)}>
            {PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
        </label>
      </div>

      {protocol === 'telnet' && (
        <p className="warn">
          Telnet sends everything, including the password, in the clear. The
          tab is marked and every connection is recorded as unencrypted. Most
          equipment that offers telnet also offers SSH.
        </p>
      )}

      <div className="row">
        {!isSerial && (
          <label>
            Port
            <input value={port} onChange={(e) => setPort(e.target.value)}
                   inputMode="numeric" placeholder="inherited" />
          </label>
        )}

        <label className="grow">
          {isSerial ? 'Username to log in with' : 'Username on the remote host'}
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 placeholder="inherited from the folder" />
        </label>
      </div>

      {isSerial && (
        <fieldset>
          <legend>Line settings</legend>
          <p className="muted">
            Blank is 9600 8N1 with no handshaking, which is what essentially
            all network equipment ships with. Half the reason a console shows
            nothing but rubbish is a speed that does not match the device.
          </p>
          <div className="row">
            <label>
              Speed
              <select value={baud} onChange={(e) => setBaud(e.target.value)}>
                <option value="">9600 (default)</option>
                {BAUD_RATES.map((rate) => (
                  <option key={rate} value={rate}>{rate}</option>
                ))}
              </select>
            </label>
            <label>
              Parity
              <select value={parity} onChange={(e) => setParity(e.target.value)}>
                <option value="">None (default)</option>
                <option value="even">Even</option>
                <option value="odd">Odd</option>
              </select>
            </label>
            <label>
              Flow control
              <select value={flow} onChange={(e) => setFlow(e.target.value)}>
                <option value="">None (default)</option>
                <option value="rtscts">Hardware (RTS/CTS)</option>
                <option value="xonxoff">Software (XON/XOFF)</option>
              </select>
            </label>
          </div>
        </fieldset>
      )}

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

      {!isSSH && (
        <details>
          <summary>Logon actions</summary>
          <p className="muted">
            {protocol === 'telnet' ? 'Telnet' : 'A serial line'} has no
            authentication of its own — there is a login prompt, and something
            has to type at it. Leave this empty and the stored credential is
            used with a sequence that suits Cisco and Unix alike; add steps to
            control it.
          </p>
          <p className="warn">
            Use <code>%PASSWORD%</code> rather than typing the password here.
            The placeholder is filled in from the credential at connect time;
            a literal password would be stored unencrypted.
          </p>

          {logonSteps.map((step, index) => (
            <div className="row" key={index}>
              <label className="grow">
                Wait for
                <input value={step.expect}
                       onChange={(e) => setStep(index, { expect: e.target.value })}
                       placeholder="ogin:|sername:" />
              </label>
              <label className="grow">
                Then send
                <input value={step.send}
                       onChange={(e) => setStep(index, { send: e.target.value })}
                       placeholder="%USERNAME%\r" />
              </label>
              <button type="button"
                      onClick={() => setLogonSteps((prev) => prev.filter((_, i) => i !== index))}>
                Remove
              </button>
            </div>
          ))}

          <button type="button"
                  onClick={() => setLogonSteps((prev) => [...prev, { expect: '', send: '' }])}>
            Add a step
          </button>
        </details>
      )}

      {isSSH && (
      <fieldset>
        <legend>Jump hosts</legend>
        <p className="muted">
          Reached through these, in order, the way OpenSSH{"'"}s ProxyJump works.
          Each hop is a saved connection with its own credential and its own
          host key check, and one bastion is shared by every connection behind
          it rather than dialled again for each.
        </p>

        {jumpChain.map((hop, index) => (
          <label key={index}>
            Hop {index + 1}
            <select value={hop} onChange={(e) => setHop(index, e.target.value)}>
              <option value="">Remove this hop</option>
              {candidates.map((c) => (
                <option key={c.id} value={c.id}>{c.name} · {c.hostname}</option>
              ))}
            </select>
          </label>
        ))}

        <label>
          Add a jump host
          <select
            value=""
            onChange={(e) => {
              if (e.target.value) setJumpChain((prev) => [...prev, e.target.value])
            }}
          >
            <option value="">Choose a saved connection…</option>
            {candidates.map((c) => (
              <option key={c.id} value={c.id}>{c.name} · {c.hostname}</option>
            ))}
          </select>
        </label>
      </fieldset>
      )}

      {isSSH && (
      <details>
        <summary>Agent forwarding</summary>
        <p className="muted">
          Offers the keys you choose to this host, so you can authenticate
          onward from it without the keys ever being on the remote machine.
        </p>
        <p className="warn">
          While this connection is open, the host can use these keys to
          authenticate anywhere they are accepted, and there is no way to tell
          its use from yours. Choose only what the host needs, and only on
          hosts you trust. This cannot be set on a folder.
        </p>

        {keyCredentials.length === 0 ? (
          <p className="muted">You have no SSH keys stored. Only keys can be forwarded.</p>
        ) : (
          keyCredentials.map((c) => (
            <label key={c.id} className="check">
              <input
                type="checkbox"
                checked={agentKeys.includes(c.id)}
                onChange={(e) =>
                  setAgentKeys((prev) =>
                    e.target.checked ? [...prev, c.id] : prev.filter((id) => id !== c.id),
                  )
                }
              />
              {c.name} · {c.key_type || 'key'}
            </label>
          ))
        )}
      </details>
      )}

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
