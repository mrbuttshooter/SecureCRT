import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SearchAddon } from '@xterm/addon-search'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import type { LiveTerminal } from '../api'
import { TerminalSocket, type HostKeyInfo, type LinkState, type TriggerEvent } from './socket'
import { HostKeyDialog } from './HostKeyDialog'
import { BroadcastMenu, SnippetMenu } from './SessionTools'
import { Highlighter } from './highlight'
import { THEMES, type ThemeName } from './themes'
import { registerHighlighter, registerTerminal, unregisterTerminal } from './screen'
import { commandFor } from './keys'

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

  /** Ask before pasting more than one line. A preference, default on. */
  pasteGuard: boolean

  /**
   * The user's other live terminals, for the broadcast group.
   *
   * Passed in rather than fetched here: the workspace already polls for them
   * to show what survived a reload, and a second poll per open pane would be
   * one request per tab per refresh for the same answer.
   */
  otherTerminals: LiveTerminal[]

  onTerminalID: (id: string) => void
  onEnded: (reason: string) => void
  /** The pane redialled: the tab's record of death should be cleared. */
  onReconnected?: () => void
}

/** A notice on the pane: a rule fired, a warning, a snippet went out. */
interface Notice {
  id: number
  kind: 'trigger' | 'warning' | 'info'
  text: string
}

/** How many notices are kept before the oldest is dropped. */
const MAX_NOTICES = 6

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

  const [notices, setNotices] = useState<Notice[]>([])
  const [pendingPaste, setPendingPaste] = useState<string | null>(null)
  const [dims, setDims] = useState<{ cols: number; rows: number } | null>(null)
  const [linesBack, setLinesBack] = useState(0)
  const [recorded, setRecorded] = useState(false)
  const [terminalId, setTerminalId] = useState(props.terminalId ?? '')
  const [group, setGroup] = useState<string[]>([])
  const [menu, setMenu] = useState<'none' | 'snippets' | 'broadcast'>('none')

  const nextNotice = useRef(0)

  // Safe for the mount-once effect below to capture: it touches only a ref
  // and a functional setState, both of which are stable, so the copy taken on
  // the first render stays correct for the life of the pane.
  const say = (kind: Notice['kind'], text: string) => {
    if (!text) return
    setNotices((prev) => {
      const next = [...prev, { id: nextNotice.current++, kind, text }]
      return next.length > MAX_NOTICES ? next.slice(next.length - MAX_NOTICES) : next
    })
  }

  // The mount-once closure needs the current link state; a ref mirrors it.
  const stateRef = useRef<LinkState>('opening')
  stateRef.current = state

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
      // The ruler down the right-hand edge is where highlight marks appear.
      // Without a width it is not drawn at all, and a highlight in a
      // ten-thousand-line scrollback is only useful if you can see where it
      // is without scrolling to it.
      overviewRuler: { width: 12, showTopBorder: true },
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

    const marks = new Highlighter(xterm, {
      onNotice: (message) => say('warning', message),
    })
    registerHighlighter(callbacks.current.paneKey, marks)

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
        onTerminalID: (id) => {
          setTerminalId(id)
          callbacks.current.onTerminalID(id)
        },
        onHighlights: (rules) => marks.setRules(rules),
        onTrigger: (event: TriggerEvent) => {
          // Highlight rules do not produce these — the server never runs one
          // — so anything arriving here is a rule that did something.
          say('trigger', `${event.name}: ${event.line}`)
        },
        onWarning: (code, message) => {
          if (code === 'session_recorded') setRecorded(true)
          say('warning', message)
        },
        onBroadcast: (terminals) => {
          setGroup(terminals)
          say(
            'info',
            terminals.length === 0
              ? 'This keyboard now reaches only this terminal.'
              : `This keyboard now reaches ${terminals.length + 1} terminals.`,
          )
        },
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

    // SecureCRT muscle memory: selecting copies, right-click pastes. The
    // selection goes to the clipboard as it is made, so select-then-rightclick
    // works between two panes the way it does between two PuTTY windows.
    const copyOnSelect = xterm.onSelectionChange(() => {
      const selection = xterm.getSelection()
      if (!selection) return
      navigator.clipboard?.writeText(selection).catch(() => {
        // The page was not focused, or the browser said no. Ctrl+C still works.
      })
    })

    // Every paste funnels through one gate. Multi-line text stops for a
    // confirmation, because on the devices this product drives — IOS, NX-OS,
    // JunOS — bracketed paste is off and every newline executes on arrival.
    // One misdirected right-click must not configure a core switch.
    const gatePaste = (text: string) => {
      if (!text) return
      const multiline = /[\r\n]/.test(text.replace(/[\r\n]+$/, ''))
      if (multiline && callbacks.current.pasteGuard) setPendingPaste(text)
      else xterm.paste(text)
    }

    const screen = host.current
    const onContextMenu = (event: MouseEvent) => {
      event.preventDefault()
      navigator.clipboard
        ?.readText()
        .then(gatePaste)
        .catch(() => {
          say('warning',
            'The browser refused clipboard access. Allow it in the address bar, or paste with Ctrl+Shift+V.')
        })
    }
    screen?.addEventListener('contextmenu', onContextMenu)

    // Capture phase, so this runs before xterm's own paste handling: the
    // event must be stopped here or the bytes are already on the wire.
    const onPaste = (event: ClipboardEvent) => {
      const text = event.clipboardData?.getData('text/plain') ?? ''
      const multiline = /[\r\n]/.test(text.replace(/[\r\n]+$/, ''))
      if (!multiline || !callbacks.current.pasteGuard) return
      event.preventDefault()
      event.stopPropagation()
      setPendingPaste(text)
    }
    screen?.addEventListener('paste', onPaste, true)

    // App chords are claimed before xterm can forward them to the host:
    // returning false stops the ESC-sequence from reaching the switch, while
    // the DOM event still bubbles to the workspace's own listener, which is
    // where tab switching actually happens.
    xterm.attachCustomKeyEventHandler((event) => {
      if (event.type !== 'keydown') return true
      // A dead pane answers Enter with a redial — the thing every engineer
      // tries first anyway. SecureCRT never had this; people asked.
      if (event.key === 'Enter' && stateRef.current === 'ended') {
        event.preventDefault()
        reconnectRef.current()
        return false
      }
      const command = commandFor(event)
      if (!command) return true
      if (command.kind === 'find') {
        event.preventDefault()
        setShowSearch(true)
        return false
      }
      if (command.kind === 'broadcast') {
        event.preventDefault()
        setMenu((m) => (m === 'broadcast' ? 'none' : 'broadcast'))
        return false
      }
      // Everything else is claimed from xterm and left to bubble up to the
      // workspace's listener, which owns tabs and the sidebar.
      return false
    })

    // The readouts SecureCRT keeps in its status bar: the grid, and how far
    // back in the scrollback you are — because "why is my command not doing
    // anything" is so often "you are four thousand lines up".
    const sizeChanged = xterm.onResize(({ cols, rows }) => setDims({ cols, rows }))
    setDims({ cols: xterm.cols, rows: xterm.rows })
    const scrolled = xterm.onScroll(() => {
      const buffer = xterm.buffer.active
      setLinesBack(buffer.baseY - buffer.viewportY)
    })
    const wrote = xterm.onWriteParsed(() => {
      const buffer = xterm.buffer.active
      setLinesBack(buffer.baseY - buffer.viewportY)
    })

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
      copyOnSelect.dispose()
      sizeChanged.dispose()
      scrolled.dispose()
      wrote.dispose()
      screen?.removeEventListener('contextmenu', onContextMenu)
      screen?.removeEventListener('paste', onPaste, true)
      marks.dispose()
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

  // The tab's own record of death follows the pane state rather than only
  // the socket's close event: a session that failed at the handshake never
  // gets a close frame, and without this the sidebar dot stayed amber on a
  // terminal whose pane already said Ended.
  useEffect(() => {
    if (state === 'ended') callbacks.current.onEnded(detail || 'The connection closed.')
  }, [state, detail])

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

  const reconnectRef = useRef<() => void>(() => {})

  // Reconnect redials in place: same pane, same xterm, same scrollback. What
  // the switch printed before it dropped you is usually the thing you were
  // reading, so recreating the terminal would destroy the evidence. A rule is
  // written into the buffer so old output and new cannot be confused.
  const reconnect = () => {
    const sock = socket.current
    const xterm = term.current
    if (!sock || !xterm || !sock.canReopen) return
    setFailure(null)
    setChanged(null)
    const at = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    xterm.writeln(`\r\n\x1b[2m\u2500\u2500\u2500 reconnecting ${at} \u2500\u2500\u2500\x1b[0m`)
    if (sock.reopen()) callbacks.current.onReconnected?.()
  }

  reconnectRef.current = reconnect

  const canReconnect = Boolean(socket.current?.canReopen)

  const setBroadcast = (terminals: string[]) => {
    // Set on the server, which re-checks every terminal against this user
    // before anything reaches it. The state here follows the acknowledgement
    // rather than leading it: showing a group the server refused would be a
    // lie about where the keys are going.
    socket.current?.broadcast(terminals)
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
        <PaneFacts
          terminalId={terminalId}
          terminals={props.otherTerminals}
          dims={dims}
        />
        {state === 'ended' && canReconnect && (
          <button className="link" onClick={reconnect}>Reconnect</button>
        )}
        {linesBack > 0 && (
          <button className="link lines-back"
                  title="Jump back to the live end of the scrollback"
                  onClick={() => term.current?.scrollToBottom()}>
            {linesBack} lines up {'↓'}
          </button>
        )}
        {recorded && (
          <span className="tag warn-tag" title="Output is being written to a transcript">
            recording
          </span>
        )}
        {group.length > 0 && (
          <span className="tag warn-tag" data-testid="broadcast-badge">
            typing into {group.length + 1}
          </span>
        )}
        <div className="pane-tools">
          <button className="link" onClick={() => setShowSearch((s) => !s)}>
            {showSearch ? 'Hide search' : 'Search'}
          </button>
          <button
            className="link"
            disabled={!terminalId}
            onClick={() => setMenu((m) => (m === 'snippets' ? 'none' : 'snippets'))}
          >
            Snippets
          </button>
          <button
            className={'link' + (group.length > 0 ? ' active' : '')}
            disabled={!terminalId}
            onClick={() => setMenu((m) => (m === 'broadcast' ? 'none' : 'broadcast'))}
          >
            Broadcast
          </button>
        </div>
      </div>

      {menu === 'snippets' && terminalId && (
        <SnippetMenu
          terminalId={terminalId}
          alsoTo={group}
          onClose={() => setMenu('none')}
          onSent={(message) => say('info', message)}
        />
      )}

      {menu === 'broadcast' && terminalId && (
        <BroadcastMenu
          terminalId={terminalId}
          candidates={props.otherTerminals}
          group={group}
          onChange={setBroadcast}
          onClose={() => setMenu('none')}
        />
      )}

      {notices.length > 0 && (
        <ul className="pane-notices" data-testid="pane-notices">
          {notices.map((notice) => (
            <li key={notice.id} className={`notice-${notice.kind}`}>
              <span>{notice.text}</span>
              <button
                className="link"
                aria-label="Dismiss"
                onClick={() => setNotices((prev) => prev.filter((n) => n.id !== notice.id))}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

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
            {canReconnect && (
              <div className="row">
                <button className="primary" onClick={reconnect}>Reconnect</button>
                <span className="muted">or press Enter</span>
              </div>
            )}
          </div>
        </div>
      )}

      {pendingPaste !== null && (
        <div className="pane-overlay">
          <div className="card" role="alertdialog" aria-label="Confirm this paste">
            <h2>
              Paste {pendingPaste.split('\n').length} lines
              {group.length > 0 ? ` into ${group.length + 1} terminals` : ''}?
            </h2>
            {group.length > 0 && (
              <p className="warn">
                This keyboard is broadcasting: every terminal in the group
                receives all of it.
              </p>
            )}
            <p className="muted">
              Each line runs as it arrives {'—'} network devices do not wait
              for the end of a paste.
            </p>
            <pre className="paste-preview">{pendingPaste}</pre>
            <div className="row">
              <button className="primary" autoFocus
                      onClick={() => { term.current?.paste(pendingPaste); setPendingPaste(null); term.current?.focus() }}>
                Paste
              </button>
              <button onClick={() => { setPendingPaste(null); term.current?.focus() }}>
                Cancel
              </button>
            </div>
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

/**
 * PaneFacts is the always-on part of the status bar: who and where this
 * terminal is, whether it is encrypted, and the grid. All of it comes from
 * state already in the browser — the live-terminals list the workspace polls
 * and the xterm instance itself — so it costs no extra request.
 */
function PaneFacts({ terminalId, terminals, dims }: {
  terminalId: string
  terminals: LiveTerminal[]
  dims: { cols: number; rows: number } | null
}) {
  const info = terminals.find((t) => t.id === terminalId)
  return (
    <span className="pane-facts">
      {info && (
        <span className="mono">
          {info.username ? `${info.username}@` : ''}{info.host}
          {info.port ? `:${info.port}` : ''}
        </span>
      )}
      {info && !info.encrypted && (
        <span className="tag warn-tag" title="This protocol sends everything, including passwords, in the clear">
          not encrypted
        </span>
      )}
      {dims && <span className="mono dims">{dims.cols}{'×'}{dims.rows}</span>}
    </span>
  )
}
