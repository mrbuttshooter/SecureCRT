import { useEffect, useState } from 'react'
import { ApiError, api, type LiveTerminal, type Snippet } from '../api'

// The two things a terminal pane can do to other terminals: send one of your
// saved commands, and put this keyboard onto several sessions at once.
//
// Both live here rather than in TerminalPane because both are lists that have
// to be fetched, and the pane is already the most load-bearing component in
// the application. Neither holds a session; they act on one they are given.

export interface SnippetMenuProps {
  /** The terminal this pane is showing. */
  terminalId: string
  /** The rest of the broadcast group, so a snippet follows the keyboard. */
  alsoTo: string[]
  onClose: () => void
  onSent: (message: string) => void
}

/**
 * SnippetMenu picks a snippet, asks for its parameters, and sends it.
 *
 * Sending goes through the API rather than through this pane's socket, and
 * that is deliberate: the server writes it to every terminal in the group in
 * one request, checks each one belongs to the user, and records a single
 * audit entry naming the snippet. Typing it down the socket instead would be
 * a keystroke stream nothing could attribute.
 */
export function SnippetMenu(props: SnippetMenuProps) {
  const [snippets, setSnippets] = useState<Snippet[] | null>(null)
  const [chosen, setChosen] = useState<Snippet | null>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [error, setError] = useState<string | null>(null)
  const [sending, setSending] = useState(false)

  useEffect(() => {
    void api
      .get<{ snippets: Snippet[] | null }>('/api/snippets')
      .then((r) => setSnippets(r.snippets ?? []))
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err))
        setSnippets([])
      })
  }, [])

  const send = async (snippet: Snippet) => {
    setSending(true)
    setError(null)
    try {
      const terminals = [props.terminalId, ...props.alsoTo]
      await api.post('/api/snippets/send', {
        snippet_id: snippet.id, values, terminals,
      })
      props.onSent(
        terminals.length > 1
          ? `Sent “${snippet.name}” to ${terminals.length} terminals.`
          : `Sent “${snippet.name}”.`,
      )
      props.onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="pane-popover" role="dialog" aria-label="Send a snippet">
      {error && <div className="error">{error}</div>}

      {snippets === null && <p className="muted">Loading…</p>}

      {snippets?.length === 0 && (
        <p className="muted">
          No snippets yet. Add them under Snippets in the menu above.
        </p>
      )}

      {!chosen && snippets && snippets.length > 0 && (
        <ul className="plain">
          {snippets.map((snippet) => (
            <li key={snippet.id}>
              <button
                className="link"
                onClick={() => {
                  if (snippet.parameters.length === 0) void send(snippet)
                  else {
                    setValues(Object.fromEntries(snippet.parameters.map((p) => [p, ''])))
                    setChosen(snippet)
                  }
                }}
              >
                {snippet.name}
              </button>
              {snippet.description && <span className="muted"> · {snippet.description}</span>}
            </li>
          ))}
        </ul>
      )}

      {chosen && (
        <form
          onSubmit={(e) => { e.preventDefault(); void send(chosen) }}
        >
          <h3>{chosen.name}</h3>
          {chosen.parameters.map((parameter) => (
            <label key={parameter}>
              {parameter}
              <input
                autoFocus={parameter === chosen.parameters[0]}
                value={values[parameter] ?? ''}
                onChange={(e) => setValues((v) => ({ ...v, [parameter]: e.target.value }))}
              />
            </label>
          ))}
          <p className="muted">
            Values are used once and not stored, here or on the server.
          </p>
          <div className="row">
            <button type="submit" disabled={sending}>
              {sending ? 'Sending…' : props.alsoTo.length > 0
                ? `Send to ${props.alsoTo.length + 1} terminals`
                : 'Send'}
            </button>
            <button type="button" onClick={() => setChosen(null)}>Back</button>
          </div>
        </form>
      )}

      <div className="row">
        <button onClick={props.onClose}>Close</button>
      </div>
    </div>
  )
}

export interface BroadcastMenuProps {
  /** This pane's terminal, which is always in the group and never listed. */
  terminalId: string
  /** Every other terminal this user has open. */
  candidates: LiveTerminal[]
  /** The group as it stands, not counting this terminal. */
  group: string[]
  onChange: (terminals: string[]) => void
  onClose: () => void
}

/**
 * BroadcastMenu chooses the terminals this keyboard also reaches.
 *
 * The group is set on the server, per browser session, and lasts only as long
 * as this socket. That is the safety property worth having: a broadcast that
 * outlived the window it was set up in is how somebody reloads a page and
 * types `reload` into forty switches.
 */
export function BroadcastMenu(props: BroadcastMenuProps) {
  const others = props.candidates.filter((t) => t.id !== props.terminalId && !t.closed)

  const toggle = (id: string, on: boolean) => {
    props.onChange(on ? [...props.group, id] : props.group.filter((x) => x !== id))
  }

  return (
    <div className="pane-popover" role="dialog" aria-label="Broadcast to other terminals">
      <h3>Type into several terminals</h3>

      {others.length === 0 ? (
        <p className="muted">
          You have no other terminals open. Open the rest of the rack and they
          will appear here.
        </p>
      ) : (
        <>
          <ul className="plain" data-testid="broadcast-candidates">
            {others.map((terminal) => (
              <li key={terminal.id}>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={props.group.includes(terminal.id)}
                    onChange={(e) => toggle(terminal.id, e.target.checked)}
                  />
                  {terminal.label || terminal.host}
                  {!terminal.encrypted && <> <span className="tag warn-tag">not encrypted</span></>}
                  {/*
                    Where it goes and when it was opened, because two windows
                    onto the same switch is an ordinary thing to have and they
                    carry the same name. A list where two rows are
                    indistinguishable is a list somebody ticks the wrong row in.
                  */}
                  <span className="muted">
                    {' · '}{terminal.device || `${terminal.host}:${terminal.port}`}
                    {' · opened '}
                    {new Date(terminal.created_at).toLocaleTimeString([], {
                      hour: '2-digit', minute: '2-digit',
                    })}
                  </span>
                </label>
              </li>
            ))}
          </ul>

          <div className="row">
            <button onClick={() => props.onChange(others.map((t) => t.id))}>Select all</button>
            <button onClick={() => props.onChange([])}>Clear</button>
          </div>
        </>
      )}

      <p className="warn">
        Everything you type reaches every terminal ticked here, including the
        keys you did not mean to press. It ends when you clear it or close this
        tab, and it is recorded.
      </p>

      <div className="row">
        <button onClick={props.onClose}>Close</button>
      </div>
    </div>
  )
}
