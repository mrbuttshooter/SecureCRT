import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SearchAddon } from '@xterm/addon-search'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import { TerminalSocket, type HostKeyInfo, type LinkState } from './socket'
import { HostKeyDialog } from './HostKeyDialog'
import { THEMES, type ThemeName } from './themes'
import { registerTerminal, unregisterTerminal } from './screen'

export interface TerminalPaneProps {
  /** Stable key for this pane, unique among the open tabs. */
  paneKey: string
  /** Saved connection to dial, for a new session. */
  sessionId?: string
  /** Existing server-side terminal to reattach to. */
  terminalId?: string
  label: string
  theme: ThemeName
  fontSize: number
  scrollback: number
  /** Focus this pane when it becomes the active tab. */
  active: boolean
  onTerminalID: (id: string) => void
  onEnded: (reason: string) => void
}

/**
 * TerminalPane is one live terminal: an xterm.js instance bound to a socket.
 *
 * The xterm instance is deliberately created once and kept for the lifetime
 * of the pane, even across reconnections. Recreating it would lose the
 * scrollback the user can see, which is the thing session survival exists to
 * protect.
 */
export function TerminalPane(props: TerminalPaneProps) {
  const host = useRef<HTMLDivElement>(null)
  const term = useRef<Terminal | null>(null)
  const fit = useRef<FitAddon | null>(null)
  const search = useRef<SearchAddon | null>(null)
  const socket = useRef<TerminalSocket | null>(null)

  const [state, setState] = useState<LinkState>('opening')
  const [detail, setDetail] = useState('')
  const [prompt, setPrompt] = useState<HostKeyInfo | null>(null)
  const [changed, setChanged] = useState<{ info: HostKeyInfo; message: string } | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [finding, setFinding] = useState('')
  const [showSearch, setShowSearch] = useState(false)

  // Callbacks change on every render; the effect below must not tear the
  // terminal down when they do, so it reads them through a ref.
  const callbacks = useRef(props)
  callbacks.current = props

  useEffect(() => {
    if (!host.current) return

    const xterm = new Terminal({
      allowProposedApi: true,
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", "Cascadia Mono", "DejaVu Sans Mono", monospace',
      fontSize: callbacks.current.fontSize,
      scrollback: callbacks.current.scrollback,
      theme: THEMES[callbacks.current.theme],
      // Networking gear draws boxes with line-drawing characters constantly;
      // without this they land a column out and every table looks broken.
      allowTransparency: false,
      macOptionIsMeta: true,
      // Reporting the mouse lets htop, vim and mc behave as they do natively.
      rightClickSelectsWord: false,
      convertEol: false,
    })

    const fitAddon = new FitAddon()
    const searchAddon = new SearchAddon()
    xterm.loadAddon(fitAddon)
    xterm.loadAddon(searchAddon)
    xterm.loadAddon(new WebLinksAddon())

    const unicode = new Unicode11Addon()
    xterm.loadAddon(unicode)
    // Width tables changed in Unicode 11; without this, emoji and CJK in a
    // prompt push everything after them one column left.
    xterm.unicode.activeVersion = '11'

    xterm.open(host.current)

    // The WebGL renderer is what keeps a fast `cat` from pegging a core. It
    // needs a GPU context, so fall back rather than failing: a terminal that
    // renders slowly is far better than one that does not render.
    try {
      const webgl = new WebglAddon()
      webgl.onContextLoss(() => webgl.dispose())
      xterm.loadAddon(webgl)
    } catch {
      // The DOM renderer stays in place.
    }

    fitAddon.fit()

    term.current = xterm
    fit.current = fitAddon
    search.current = searchAddon
    registerTerminal(callbacks.current.paneKey, xterm)

    const sock = new TerminalSocket(
      {
        sessionId: callbacks.current.sessionId,
        terminalId: callbacks.current.terminalId,
        cols: xterm.cols,
        rows: xterm.rows,
      },
      {
        onData: (bytes) => xterm.write(bytes),
        onState: (next, why) => {
          setState(next)
          setDetail(why ?? '')
        },
        onHostKeyPrompt: setPrompt,
        onHostKeyChanged: (info, message) => setChanged({ info, message }),
        onError: (_code, message) => setFailure(message),
        onTerminalID: (id) => callbacks.current.onTerminalID(id),
        onClosed: (exit) => {
          callbacks.current.onEnded(
            exit === undefined || exit === 0
              ? 'The session ended.'
              : `The session ended with status ${exit}.`,
          )
        },
      },
    )
    socket.current = sock

    // Keystrokes go out as UTF-8 bytes rather than as text frames: the
    // protocol reserves text frames for control messages, and a keystroke
    // that happened to be valid JSON would otherwise be ambiguous.
    const encoder = new TextEncoder()
    const typed = xterm.onData((data) => sock.send(encoder.encode(data)))
    // onBinary carries what xterm could not represent as a string, which
    // arrives when a program puts the terminal in a raw 8-bit mode.
    const binary = xterm.onBinary((data) => {
      const bytes = new Uint8Array(data.length)
      for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xff
      sock.send(bytes)
    })

    sock.open()

    // ResizeObserver rather than a window listener: a split pane changes size
    // without the window doing anything.
    const observer = new ResizeObserver(() => {
      try {
        fitAddon.fit()
        sock.resize(xterm.cols, xterm.rows)
      } catch {
        // fit() throws while the pane is hidden and has no dimensions.
      }
    })
    observer.observe(host.current)

    return () => {
      observer.disconnect()
      unregisterTerminal(callbacks.current.paneKey)
      typed.dispose()
      binary.dispose()
      sock.close()
      xterm.dispose()
      term.current = null
      socket.current = null
    }
    // Deliberately empty: the pane is bound to one terminal for its lifetime,
    // and a re-run would drop the session it is displaying.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Appearance changes apply in place, without disturbing the session.
  useEffect(() => {
    if (!term.current) return
    term.current.options.theme = THEMES[props.theme]
    term.current.options.fontSize = props.fontSize
    term.current.options.scrollback = props.scrollback
    try {
      fit.current?.fit()
      socket.current?.resize(term.current.cols, term.current.rows)
    } catch {
      // hidden pane
    }
  }, [props.theme, props.fontSize, props.scrollback])

  useEffect(() => {
    if (!props.active || !term.current) return
    // A tab that has just been shown had no dimensions a moment ago, so it
    // needs measuring before it can take focus usefully.
    const id = window.setTimeout(() => {
      try {
        fit.current?.fit()
        socket.current?.resize(term.current!.cols, term.current!.rows)
      } catch {
        // still measuring
      }
      term.current?.focus()
    }, 0)
    return () => window.clearTimeout(id)
  }, [props.active])

  const answerHostKey = (accepted: boolean) => {
    setPrompt(null)
    socket.current?.answerHostKey(accepted)
  }

  const runSearch = (next: string, forward = true) => {
    setFinding(next)
    if (!next) return
    if (forward) search.current?.findNext(next)
    else search.current?.findPrevious(next)
  }

  return (
    <div
      className="pane"
      data-testid="terminal-pane"
      data-pane-key={props.paneKey}
      data-state={state}
    >
      <div className="pane-status" role="status">
        <StatusPill state={state} detail={detail} />
        <span className="pane-label">{props.label}</span>
        <div className="pane-tools">
          <button className="link" onClick={() => setShowSearch((s) => !s)}>
            {showSearch ? 'Hide search' : 'Search'}
          </button>
        </div>
      </div>

      {showSearch && (
        <div className="pane-search">
          <input
            autoFocus
            aria-label="Search the scrollback"
            value={finding}
            placeholder="Find in scrollback"
            onChange={(e) => runSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') runSearch(finding, !e.shiftKey)
              if (e.key === 'Escape') {
                setShowSearch(false)
                term.current?.focus()
              }
            }}
          />
          <button onClick={() => runSearch(finding, false)}>Previous</button>
          <button onClick={() => runSearch(finding, true)}>Next</button>
        </div>
      )}

      <div className="pane-screen" ref={host} />

      {prompt && (
        <HostKeyDialog
          info={prompt}
          onAccept={() => answerHostKey(true)}
          onReject={() => answerHostKey(false)}
        />
      )}

      {changed && (
        <div className="pane-overlay">
          <div className="card danger" role="alertdialog" aria-label="The host key has changed">
            <h2>The host key has changed</h2>
            <p>{changed.message}</p>
            <dl className="facts">
              <dt>Host</dt>
              <dd>{changed.info.hostname}:{changed.info.port}</dd>
              <dt>Now offering</dt>
              <dd><code>{changed.info.fingerprint}</code></dd>
              <dt>Previously</dt>
              <dd><code>{changed.info.previous_fingerprint}</code></dd>
              {changed.info.previously_seen && (
                <>
                  <dt>Trusted since</dt>
                  <dd>{new Date(changed.info.previously_seen).toLocaleDateString()}</dd>
                </>
              )}
            </dl>
            <p className="muted">
              Either the host was rebuilt, or something is impersonating it. No
              credential was sent. Confirm the new fingerprint out of band, then
              remove the old entry under Known hosts before connecting again.
            </p>
            {changed.info.org_wide && (
              <p className="muted">
                This entry was published by an administrator, so only they can
                change it.
              </p>
            )}
          </div>
        </div>
      )}

      {failure && !changed && (
        <div className="pane-overlay">
          <div className="card" role="alert">
            <h2>Could not connect</h2>
            <p>{failure}</p>
          </div>
        </div>
      )}
    </div>
  )
}

const STATE_LABELS: Record<LinkState, string> = {
  opening: 'Opening',
  connecting: 'Connecting',
  prompting: 'Waiting for you',
  live: 'Connected',
  reconnecting: 'Reconnecting',
  ended: 'Ended',
}

const DETAIL_LABELS: Record<string, string> = {
  dialling: 'Dialling',
  verifying_host: 'Checking the host key',
  authenticating: 'Authenticating',
}

function StatusPill({ state, detail }: { state: LinkState; detail: string }) {
  const text = DETAIL_LABELS[detail] ?? STATE_LABELS[state]
  return <span className={`pill pill-${state}`}>{text}</span>
}
