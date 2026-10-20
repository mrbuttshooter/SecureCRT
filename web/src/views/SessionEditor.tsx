import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import {
  ApiError, api,
  type Credential, type LogonStep, type SavedSession, type Settings,
  type Trigger, type Tree,
} from '../api'
import { TriggerEditor } from './TriggerEditor'
import { AppearanceFields } from './AppearanceFields'
import './options.css'

export interface SessionEditorProps {
  /** The connection being edited, or null when creating one. */
  session: SavedSession | null
  folderId: string
  onSaved: (session: SavedSession, connect: boolean) => void
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

type Protocol = (typeof PROTOCOLS)[number]['value']

/**
 * emptyMeans turns the list the form holds back into what is saved, for the
 * lists where null and [] differ: null inherits from the folder, [] opts out
 * of it. A non-empty list is saved as is. An empty one stays [] only if the
 * connection was saved with [] — an explicit opt-out nobody touched — and is
 * otherwise null, so removing the last rule means "inherit", not "keep the
 * rules I just deleted".
 */
function emptyMeans<T>(current: T[], saved: T[] | null | undefined): T[] | null {
  if (current.length > 0) return current
  return Array.isArray(saved) && saved.length === 0 ? [] : null
}

type Category =
  | 'connection' | 'serial' | 'jump' | 'agent' | 'logon'
  | 'triggers' | 'appearance' | 'log' | 'advanced'

// The category list down the left of SecureCRT's Session Options, trimmed to
// what this protocol can use: a serial line has no jump hosts, and SSH has no
// login prompt to type at.
const CATEGORIES: { id: Category; label: string; when?: (p: Protocol) => boolean }[] = [
  { id: 'connection', label: 'Connection' },
  { id: 'serial', label: 'Serial line', when: (p) => p === 'serial' },
  { id: 'jump', label: 'Jump hosts', when: (p) => p === 'ssh' },
  { id: 'agent', label: 'Agent forwarding', when: (p) => p === 'ssh' },
  { id: 'logon', label: 'Logon actions', when: (p) => p !== 'ssh' },
  { id: 'triggers', label: 'Watch rules' },
  { id: 'appearance', label: 'Appearance' },
  { id: 'log', label: 'Log file' },
  { id: 'advanced', label: 'Advanced' },
]

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
  const [protocol, setProtocol] = useState<Protocol>(editing?.protocol ?? 'ssh')
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
  const [scheme, setScheme] = useState(editing?.settings?.colour_scheme ?? '')
  const [fontSize, setFontSize] = useState(
    editing?.settings?.font_size != null ? String(editing.settings.font_size) : '',
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

  const [triggers, setTriggers] = useState<Trigger[]>(editing?.settings?.triggers ?? [])

  // A transcript is written on the server, so it is not a local preference
  // and does not belong in the appearance menu with the font size.
  const [logSession, setLogSession] = useState(
    editing?.settings?.log_session ?? false,
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
  // Whether the pressed button asked for a connection as well as a save.
  const connectAfter = useRef(false)

  // Which category's fields are showing. Every field's state lives above, so
  // switching only changes what is on screen; the one form still saves all.
  const [category, setCategory] = useState<Category>('connection')
  const panelRef = useRef<HTMLDivElement>(null)
  const tabId = useId()

  useEffect(() => {
    const fetchCredentials = () => {
      void api
        .get<{ credentials: Credential[] }>('/api/credentials')
        .then((r) => setCredentials(r.credentials ?? []))
        .catch(() => setCredentials([]))
    }
    fetchCredentials()
    // Refetched on focus: the workspace stays mounted across tab switches,
    // so a credential created on the Credentials tab mid-form would
    // otherwise never appear in this dropdown.
    window.addEventListener('focus', fetchCredentials)
    document.addEventListener('visibilitychange', fetchCredentials)
    return () => {
      window.removeEventListener('focus', fetchCredentials)
      document.removeEventListener('visibilitychange', fetchCredentials)
    }
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

  // Switching protocol can hide the category being shown (Jump hosts, say,
  // on a change to telnet); the list then falls back to Connection rather
  // than showing a panel for something this protocol does not have.
  const categories = CATEGORIES.filter((c) => !c.when || c.when(protocol))
  const shown: Category = categories.some((c) => c.id === category) ? category : 'connection'

  // TriggerEditor brings its own collapsible wrapper. Inside a panel that
  // already says "Watch rules" a second, folded heading is only a click in
  // the way, so it is opened when the panel appears.
  useLayoutEffect(() => {
    if (shown !== 'triggers') return
    const details = panelRef.current?.querySelector('details.triggers')
    if (details instanceof HTMLDetailsElement) details.open = true
  }, [shown])

  const onCategoryKey = (event: React.KeyboardEvent) => {
    const index = categories.findIndex((c) => c.id === shown)
    let next = index
    if (event.key === 'ArrowDown') next = Math.min(categories.length - 1, index + 1)
    else if (event.key === 'ArrowUp') next = Math.max(0, index - 1)
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = categories.length - 1
    else return
    const id = categories[next]?.id
    if (!id) return
    event.preventDefault()
    setCategory(id)
    document.getElementById(`${tabId}-${id}`)?.focus()
  }

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

    // Only the showing category's fields are in the page, so the browser's own
    // `required` check cannot see an empty name while Watch rules is open.
    // The same check is made here, and the fields it is about brought back.
    if (!name.trim() || !hostname.trim()) {
      setCategory('connection')
      setError(isSerial
        ? 'A connection needs a name and a serial device.'
        : 'A connection needs a name and a hostname.')
      return
    }

    setSaving(true)

    // A blank optional field is sent as null, which the server reads as
    // "inherit". Sending "" would instead pin it to empty, which is a
    // different and almost never intended thing.
    const settings: Settings = {
      // Whatever this form does not show is carried over rather than wiped:
      // an imported connection can hold settings with no field here yet.
      ...editing?.settings,
      keepalive_seconds: keepalive ? Number(keepalive) : null,
      scrollback: scrollback ? Number(scrollback) : null,
      colour_scheme: scheme || null,
      font_size: fontSize ? Number(fontSize) : null,
      // An empty list is sent as null rather than [], so "no agent" is one
      // state on the wire rather than two that have to agree.
      agent_forward_credentials: agentKeys.length > 0 ? agentKeys : null,

      // Logon steps are the opposite: null and empty mean different things.
      // Null is "say nothing", which falls back to the default sequence when
      // a password is stored; empty is "send nothing", which is how one
      // connection inside a folder opts out of the folder's sequence.
      // An empty list here is therefore only kept when it was saved that way;
      // a connection that had steps and has had them all removed goes back
      // to null and inherits, rather than quietly re-saving the old steps.
      logon_steps: emptyMeans(logonSteps, editing?.settings?.logon_steps),

      serial_baud: isSerial && baud ? Number(baud) : null,
      serial_parity: isSerial && parity ? parity : null,
      serial_flow: isSerial && flow ? flow : null,
      // No field here sets these yet — an import can — so a serial line keeps
      // what it has, and anything else drops them with the rest of the line.
      serial_data_bits: isSerial ? editing?.settings?.serial_data_bits ?? null : null,
      serial_stop_bits: isSerial ? editing?.settings?.serial_stop_bits ?? null : null,

      // Same reasoning as the logon steps: an empty list is not "no rules",
      // it is "no rules here", which is how a connection opts out of a
      // folder's rules. Null is silence, and silence inherits.
      triggers: emptyMeans(triggers, editing?.settings?.triggers),

      log_session: logSession ? true : null,
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
      props.onSaved(saved, connectAfter.current)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  const label = categories.find((c) => c.id === shown)?.label ?? ''

  return (
    <form className="editor opt-dialog" onSubmit={submit}>
      <div className="opt-body">
        <div className="opt-categories" role="tablist" aria-orientation="vertical"
             aria-label="Category" onKeyDown={onCategoryKey}>
          {categories.map((c) => (
            <button key={c.id} type="button" role="tab" id={`${tabId}-${c.id}`}
                    aria-selected={c.id === shown} aria-controls={`${tabId}-panel`}
                    tabIndex={c.id === shown ? 0 : -1}
                    className={c.id === shown ? 'opt-category selected' : 'opt-category'}
                    onClick={() => setCategory(c.id)}>
              {c.label}
            </button>
          ))}
        </div>

        <div className="opt-panel" role="tabpanel" id={`${tabId}-panel`}
             aria-labelledby={`${tabId}-${shown}`} ref={panelRef}>
          <div className="opt-heading">{label}</div>

          {shown === 'connection' && (
            <>
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
            </>
          )}

          {shown === 'serial' && isSerial && (
            <>
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
            </>
          )}

          {shown === 'logon' && !isSSH && (
            <>
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
            </>
          )}

          {shown === 'jump' && isSSH && (
            <>
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
            </>
          )}

          {shown === 'agent' && isSSH && (
            <>
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
            </>
          )}

          {shown === 'triggers' && (
            <TriggerEditor triggers={triggers} onChange={setTriggers} scope="connection" />
          )}

          {shown === 'appearance' && (
            <AppearanceFields scheme={scheme} size={fontSize} onScheme={setScheme}
                              onSize={setFontSize} scope="connection" />
          )}

          {shown === 'log' && (
            <>
              <label className="check">
                <input
                  type="checkbox"
                  checked={logSession}
                  onChange={(e) => setLogSession(e.target.checked)}
                />
                Write a transcript of this session to the server
              </label>
              <p className="muted">
                The transcript holds what the device printed, and never what you
                typed — a keystroke log would capture passwords typed at prompts
                this server never sees. Files are written under the server{"'"}s
                transcript directory, readable only by the service account, and the
                terminal says so when a session is being recorded.
              </p>
            </>
          )}

          {shown === 'advanced' && (
            <>
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
            </>
          )}
        </div>
      </div>

      {/* Outside the panel, so a refusal from the server stays in view
          whichever category happens to be showing when OK is pressed. */}
      {error && <div className="error opt-error" role="alert">{error}</div>}

      <div className="opt-footer">
        {editing ? (
          <button type="submit" className="primary" disabled={saving}
                  onClick={() => { connectAfter.current = false }}>
            {saving ? 'Saving…' : 'OK'}
          </button>
        ) : (
          <>
            <button type="submit" className="primary" disabled={saving}
                    onClick={() => { connectAfter.current = true }}>
              {saving ? 'Saving…' : 'Create and connect'}
            </button>
            <button type="submit" disabled={saving}
                    onClick={() => { connectAfter.current = false }}>
              {saving ? 'Saving…' : 'Create only'}
            </button>
          </>
        )}
        <button type="button" onClick={props.onCancel}>Cancel</button>
      </div>
    </form>
  )
}
