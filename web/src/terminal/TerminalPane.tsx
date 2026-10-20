import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SearchAddon } from '@xterm/addon-search'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import { api, type LiveTerminal } from '../api'
import { TerminalSocket, type HostKeyInfo, type LinkState, type TriggerEvent } from './socket'
import { HostKeyDialog } from './HostKeyDialog'
import { BroadcastMenu, SnippetMenu } from './SessionTools'
import { Highlighter } from './highlight'
import { FONT_FAMILIES, THEMES, type ThemeName } from './themes'
import { registerHighlighter, registerTerminal, unregisterTerminal } from './screen'
import { registerPane, unregisterPane, type PaneInfo } from './panes'
import { commandFor } from './keys'
import type { BellMode, CursorStyle } from './prefs'
import { ContextMenu, MENU_BREAK, type MenuItem } from '../ContextMenu'

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
  /** A key of FONT_FAMILIES. */
  fontFamily: string
  scrollback: number
  cursorStyle: CursorStyle
  cursorBlink: boolean
  /** Focus this pane when it becomes the active tab. */
  active: boolean
  /**
   * One pane on screen: the tab already names it and the window's status bar
   * carries its facts, so the pane's own header appears only when it has
   * something to say — ended, reconnecting, recording, broadcasting.
   */
  compact?: boolean

  /** Ask before pasting more than one line. A preference, default on. */
  pasteGuard: boolean
  /** Milliseconds between the lines of a multi-line paste; 0 for none. */
  lineDelayMs: number
  copyOnSelect: boolean
  rightClickPaste: boolean
  bell: BellMode
  autoReconnect: boolean

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
  /** Output arrived. Called at most about once a second. */
  onActivity?: () => void
  /** The host rang the bell. */
  onBell?: () => void
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
 * Seconds to wait before each automatic redial. Short at first, because the
 * usual cause is a blip; longer after, so a device that is rebooting is not
 * dialled forty times while it comes back.
 */
const AUTO_RECONNECT_S = [3, 5, 10, 20, 30, 60]

/** Error codes no number of retries will fix, so auto-reconnect stops. */
const FINAL_ERRORS = /auth|credential|host_key|forbidden|not_found|vault|locked|protocol|jump_chain|conflict/

/**
 * TerminalPane is one live terminal: an xterm.js instance bound to a socket.
 *
 * The xterm instance is deliberately created once and kept for the lifetime
 * of the pane, even across reconnections. Recreating it would lose the
 * scrollback the user can see, which is the thing session survival exists to
 * protect.
 */
export function TerminalPane(props: TerminalPaneProps) {
  const root = useRef<HTMLDivElement>(null)
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
  const [pasteDelay, setPasteDelay] = useState(String(props.lineDelayMs))
  const [sending, setSending] = useState<{ done: number; total: number } | null>(null)
  const [dims, setDims] = useState<{ cols: number; rows: number } | null>(null)
  const [linesBack, setLinesBack] = useState(0)
  const [recorded, setRecorded] = useState(false)
  const [terminalId, setTerminalId] = useState(props.terminalId ?? '')
  const [group, setGroup] = useState<string[]>([])
  const [menu, setMenu] = useState<'none' | 'snippets' | 'broadcast'>('none')
  const [paneMenu, setPaneMenu] = useState<{ x: number; y: number } | null>(null)
  /** Steps of text size away from what the tab would otherwise use. */
  const [zoom, setZoom] = useState(0)
  const [ringing, setRinging] = useState(false)
  /** Seconds until an automatic redial, or null when none is pending. */
  const [countdown, setCountdown] = useState<number | null>(null)

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
  const groupRef = useRef<string[]>([])
  groupRef.current = group

  // Callbacks change on every render; the effect below must not tear the
  // terminal down when they do, so it reads them through a ref.
  const callbacks = useRef(props)
  callbacks.current = props

  // What auto-reconnect needs to know about how the last session ended.
  const everLive = useRef(false)
  const cleanExit = useRef(false)
  const lastError = useRef('')
  const autoTries = useRef(0)
  const autoTimer = useRef<number | null>(null)
  const sendTimer = useRef<number | null>(null)

  const effectiveSize = Math.min(32, Math.max(8, props.fontSize + zoom))

  useEffect(() => {
    if (!host.current) return

    const xterm = new Terminal({
      allowProposedApi: true,
      cursorBlink: callbacks.current.cursorBlink,
      cursorStyle: callbacks.current.cursorStyle,
      fontFamily: FONT_FAMILIES[callbacks.current.fontFamily] ?? FONT_FAMILIES.default,
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

    // Activity is reported at most about once a second: a scrolling `show
    // log` would otherwise be a state update per frame for a dot that only
    // needs to turn on once.
    let lastActivity = 0

    const sock = new TerminalSocket(
      {
        sessionId: callbacks.current.sessionId,
        terminalId: callbacks.current.terminalId,
        cols: xterm.cols,
        rows: xterm.rows,
      },
      {
        onData: (bytes) => {
          xterm.write(bytes)
          const now = Date.now()
          if (now - lastActivity > 1000) {
            lastActivity = now
            callbacks.current.onActivity?.()
          }
        },
        onState: (next, why) => {
          if (next === 'live') {
            everLive.current = true
            cleanExit.current = false
            lastError.current = ''
          }
          setState(next)
          setDetail(why ?? '')
        },
        onHostKeyPrompt: setPrompt,
        onHostKeyChanged: (info, message) => setChanged({ info, message }),
        onError: (code, message) => {
          lastError.current = code
          setFailure(message)
        },
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
        onClosed: (exit, _message, final) => {
          // The server marks an ending it meant — a logout, a closed tab, an
          // administrator — as final. Older servers do not, so an exit
          // status still counts as the shell saying goodbye.
          cleanExit.current = Boolean(final) || exit !== undefined
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
    const onMouseUp = () => {
      if (!callbacks.current.copyOnSelect || !xterm.hasSelection()) return
      navigator.clipboard?.writeText(xterm.getSelection()).catch(() => {
        // The page was not focused, or the browser said no. Ctrl+C still works.
      })
    }
    host.current.addEventListener('mouseup', onMouseUp)

    // The bell: a flash, a beep, or nothing, and in every case a mark on the
    // tab if this one is not in front — "the switch behind tab six beeped"
    // is the thing worth knowing.
    const rang = xterm.onBell(() => {
      const mode = callbacks.current.bell
      if (mode === 'visual') {
        setRinging(true)
        window.setTimeout(() => setRinging(false), 180)
      } else if (mode === 'sound') {
        beep()
      }
      callbacks.current.onBell?.()
    })

    const screen = host.current
    const onContextMenu = (event: MouseEvent) => {
      event.preventDefault()
      // Shift+right-click always opens the menu, so turning on right-click
      // paste never costs the menu its only door.
      if (callbacks.current.rightClickPaste && !event.shiftKey) {
        pasteFromClipboardRef.current()
      } else {
        setPaneMenu({ x: event.clientX, y: event.clientY })
      }
    }
    screen?.addEventListener('contextmenu', onContextMenu)

    // Capture phase, so this runs before xterm's own paste handling: the
    // event must be stopped here or the bytes are already on the wire.
    const onPaste = (event: ClipboardEvent) => {
      const text = event.clipboardData?.getData('text/plain') ?? ''
      if (!needsGate(text) && callbacks.current.lineDelayMs <= 0) return
      event.preventDefault()
      event.stopPropagation()
      gateRef.current(text)
    }
    screen?.addEventListener('paste', onPaste, true)

    // Ctrl+wheel is text size in every terminal anyone has used; here it is
    // per pane, so the one on the projector can be big without the rest.
    const onWheel = (event: WheelEvent) => {
      if (!event.ctrlKey) return
      event.preventDefault()
      setZoom((z) => z + (event.deltaY < 0 ? 1 : -1))
    }
    screen?.addEventListener('wheel', onWheel, { passive: false })

    // "Reconnect all" is one event the workspace broadcasts; each dead pane
    // answers for itself, because only the pane knows whether it can.
    const onReconnectAll = () => {
      if (stateRef.current === 'ended') reconnectRef.current()
    }
    window.addEventListener('bkd:reconnect-all', onReconnectAll)

    // App chords are claimed before xterm can forward them to the host:
    // returning false stops the ESC-sequence from reaching the switch, while
    // the DOM event still bubbles to the workspace's own listener, which is
    // where tab switching actually happens.
    xterm.attachCustomKeyEventHandler((event) => {
      if (event.type !== 'keydown') return true
      // A dead pane answers Enter with a redial — the thing every engineer
      // tries first anyway. SecureCRT never had this; people asked.
      if (event.key === 'Enter' && !event.altKey && !event.ctrlKey
          && stateRef.current === 'ended') {
        event.preventDefault()
        reconnectRef.current()
        return false
      }
      const command = commandFor(event)
      if (!command) return true
      // Every claimed chord is handled by the workspace's listener, which
      // routes pane commands back here through the pane handle; doing them
      // here as well would do them twice.
      event.preventDefault()
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

    registerPane(callbacks.current.paneKey, {
      type: (text) => sock.send(encoder.encode(text)),
      paste: (text) => gateRef.current(text),
      focus: () => xterm.focus(),
      live: () => stateRef.current === 'live',
      reach: () => groupRef.current.length + 1,
      zoom: (step) => setZoom((z) => (step === 0 ? 0 : z + step)),
      fullscreen: () => toggleFullscreenRef.current(),
      find: () => setShowSearch(true),
      broadcastMenu: () => setMenu((m) => (m === 'broadcast' ? 'none' : 'broadcast')),
      snippetsMenu: () => setMenu((m) => (m === 'snippets' ? 'none' : 'snippets')),
      // The rest change with every render, so they are read through a ref.
      copy: () => verbs.current.copy(),
      pasteClipboard: () => { pasteFromClipboardRef.current(); xterm.focus() },
      selectAll: () => { xterm.selectAll(); xterm.focus() },
      clear: () => { xterm.clear(); xterm.focus() },
      reset: () => verbs.current.reset(),
      saveOutput: () => verbs.current.saveOutput(),
      toggleRecording: () => verbs.current.toggleRecording(),
      reconnect: () => verbs.current.reconnect(),
      info: () => verbs.current.info(),
    })

    return () => {
      observer.disconnect()
      screen?.removeEventListener('mouseup', onMouseUp)
      rang.dispose()
      sizeChanged.dispose()
      scrolled.dispose()
      wrote.dispose()
      screen?.removeEventListener('contextmenu', onContextMenu)
      screen?.removeEventListener('paste', onPaste, true)
      screen?.removeEventListener('wheel', onWheel)
      window.removeEventListener('bkd:reconnect-all', onReconnectAll)
      if (autoTimer.current !== null) window.clearInterval(autoTimer.current)
      if (sendTimer.current !== null) window.clearTimeout(sendTimer.current)
      marks.dispose()
      unregisterTerminal(callbacks.current.paneKey)
      unregisterPane(callbacks.current.paneKey)
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

  // --- paste -------------------------------------------------------------

  // Every paste funnels through one gate. Multi-line text stops for a
  // confirmation, because on the devices this product drives — IOS, NX-OS,
  // JunOS — bracketed paste is off and every newline executes on arrival.
  // One misdirected right-click must not configure a core switch.
  // Returns true when the text went out now, false when it is waiting on
  // the confirmation or was refused.
  const gate = (text: string): boolean => {
    if (!text) return false
    if (sendTimer.current !== null) {
      say('warning', 'A paste is still being sent line by line. Stop it first, or wait for it to finish.')
      return false
    }
    if (needsGate(text) && callbacks.current.pasteGuard) {
      setPasteDelay(String(callbacks.current.lineDelayMs))
      setPendingPaste(text)
      return false
    }
    sendPaste(text, callbacks.current.lineDelayMs)
    return true
  }
  const gateRef = useRef(gate)
  gateRef.current = gate

  const pasteFromClipboard = () => {
    navigator.clipboard
      ?.readText()
      .then((text) => gateRef.current(text))
      .catch(() => {
        say('warning',
          'The browser refused clipboard access. Allow it in the address bar, or paste with Ctrl+Shift+V.')
      })
  }
  const pasteFromClipboardRef = useRef(pasteFromClipboard)
  pasteFromClipboardRef.current = pasteFromClipboard

  /**
   * sendPaste writes a paste to the host, all at once or a line at a time.
   *
   * With a delay, each line goes as if typed and followed by Enter, and the
   * next waits. That is what a slow console needs, and it is also what makes
   * the paste cancellable halfway — the one time you notice the wrong
   * interface name is always line nine of forty.
   *
   * A shell that has asked for bracketed paste gets the paste whole: it will
   * not run anything until the end, so there is nothing to slow down.
   */
  const sendPaste = (text: string, delayMs: number) => {
    const xterm = term.current
    const sock = socket.current
    if (!xterm || !sock) return
    const lines = text.replace(/\r\n?/g, '\n').split('\n')
    if (delayMs <= 0 || lines.length < 2 || xterm.modes.bracketedPasteMode) {
      xterm.paste(text)
      return
    }
    // A trailing newline produces an empty last element; it means "press
    // Enter after the last line", not "send an empty line".
    const endsWithNewline = lines.at(-1) === ''
    if (endsWithNewline) lines.pop()
    const encoder = new TextEncoder()
    let i = 0
    setSending({ done: 0, total: lines.length })
    const step = () => {
      if (stateRef.current !== 'live') {
        sendTimer.current = null
        setSending(null)
        say('warning', `The session ended; the paste stopped after ${i} of ${lines.length} lines.`)
        return
      }
      const last = i === lines.length - 1
      sock.send(encoder.encode(lines[i] + (last && !endsWithNewline ? '' : '\r')))
      i += 1
      if (i < lines.length) {
        setSending({ done: i, total: lines.length })
        sendTimer.current = window.setTimeout(step, delayMs)
      } else {
        sendTimer.current = null
        setSending(null)
      }
    }
    step()
  }

  const cancelSending = () => {
    if (sendTimer.current !== null) window.clearTimeout(sendTimer.current)
    sendTimer.current = null
    if (sending) say('info', `Paste stopped after ${sending.done} of ${sending.total} lines.`)
    setSending(null)
  }

  // --- reconnecting ------------------------------------------------------

  const answerHostKey = (accepted: boolean) => {
    setPrompt(null)
    socket.current?.answerHostKey(accepted)
  }

  const reconnectRef = useRef<() => void>(() => {})

  const stopCountdown = () => {
    if (autoTimer.current !== null) window.clearInterval(autoTimer.current)
    autoTimer.current = null
    setCountdown(null)
  }

  // Reconnect redials in place: same pane, same xterm, same scrollback. What
  // the switch printed before it dropped you is usually the thing you were
  // reading, so recreating the terminal would destroy the evidence. A rule is
  // written into the buffer so old output and new cannot be confused.
  const reconnect = () => {
    const sock = socket.current
    const xterm = term.current
    if (!sock || !xterm || !sock.canReopen) return
    stopCountdown()
    setFailure(null)
    setChanged(null)
    const at = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    xterm.writeln(`\r\n\x1b[2m─── reconnecting ${at} ───\x1b[0m`)
    if (sock.reopen()) callbacks.current.onReconnected?.()
  }

  reconnectRef.current = reconnect

  const canReconnect = Boolean(socket.current?.canReopen)

  // The tab's own record of death follows the pane state rather than only
  // the socket's close event: a session that failed at the handshake never
  // gets a close frame, and without this the sidebar dot stayed amber on a
  // terminal whose pane already said Ended.
  useEffect(() => {
    if (state === 'ended') callbacks.current.onEnded(detail || 'The connection closed.')
    if (state !== 'live') return
    const settled = window.setTimeout(() => { autoTries.current = 0 }, 30_000)
    return () => window.clearTimeout(settled)
  }, [state, detail])

  // Auto-reconnect, when asked for: only for a session that was up and lost
  // its connection — never after a clean logout, a changed host key, or a
  // refusal that would only be repeated. A countdown is shown, and Enter,
  // Reconnect or Cancel all take over from it.
  useEffect(() => {
    if (state !== 'ended' || !props.autoReconnect || !canReconnect) return
    if (changed || cleanExit.current || !everLive.current) return
    if (FINAL_ERRORS.test(lastError.current)) return
    if (autoTries.current >= AUTO_RECONNECT_S.length) {
      say('warning', 'Gave up reconnecting automatically. Press Enter to try again.')
      return
    }
    let left = AUTO_RECONNECT_S[autoTries.current]!
    autoTries.current += 1
    setCountdown(left)
    autoTimer.current = window.setInterval(() => {
      left -= 1
      if (left <= 0) reconnectRef.current()
      else setCountdown(left)
    }, 1000)
    return stopCountdown
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state, props.autoReconnect, changed])

  // --- appearance --------------------------------------------------------

  // Appearance changes apply in place, without disturbing the session.
  useEffect(() => {
    const xterm = term.current
    if (!xterm) return
    xterm.options.theme = THEMES[props.theme]
    xterm.options.fontSize = effectiveSize
    xterm.options.fontFamily = FONT_FAMILIES[props.fontFamily] ?? FONT_FAMILIES.default
    xterm.options.scrollback = props.scrollback
    xterm.options.cursorStyle = props.cursorStyle
    xterm.options.cursorBlink = props.cursorBlink
    try {
      fit.current?.fit()
      socket.current?.resize(xterm.cols, xterm.rows)
    } catch {
      // hidden pane
    }
  }, [props.theme, effectiveSize, props.fontFamily, props.scrollback,
      props.cursorStyle, props.cursorBlink])

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

  const toggleFullscreen = () => {
    if (document.fullscreenElement) void document.exitFullscreen()
    else void root.current?.requestFullscreen().then(() => term.current?.focus()).catch(() => {
      say('warning', 'The browser would not go full screen here.')
    })
  }
  const toggleFullscreenRef = useRef(toggleFullscreen)
  toggleFullscreenRef.current = toggleFullscreen

  // --- recording ---------------------------------------------------------

  const [recBusy, setRecBusy] = useState(false)
  const forced = props.otherTerminals.find((t) => t.id === terminalId)?.record_forced ?? false

  // The person being recorded does not get to turn the camera off when the
  // operator required it, and the interface says so rather than pretending.
  const toggleRecording = async () => {
    if (!terminalId || recBusy) return
    if (recorded && forced) {
      say('warning', 'This server requires recording; it cannot be stopped here.')
      return
    }
    setRecBusy(true)
    try {
      const r = await api.post<{ recorded: boolean }>(
        `/api/terminals/${encodeURIComponent(terminalId)}/recording`, { on: !recorded })
      setRecorded(r.recorded)
      say('info', r.recorded
        ? 'Recording started. Output from here on is written to a transcript.'
        : 'Recording stopped.')
    } catch (err) {
      say('warning', err instanceof Error ? err.message : String(err))
    } finally {
      setRecBusy(false)
    }
  }

  // --- the pane menu -----------------------------------------------------

  const bufferText = () => {
    const xterm = term.current
    if (!xterm) return ''
    const buffer = xterm.buffer.active
    const lines: string[] = []
    for (let i = 0; i < buffer.length; i++) {
      lines.push(buffer.getLine(i)?.translateToString(true) ?? '')
    }
    while (lines.length && lines.at(-1) === '') lines.pop()
    return lines.join('\n') + '\n'
  }

  const saveOutput = () => {
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-')
    const name = `${props.label.replace(/[^\w.-]+/g, '_') || 'terminal'}-${stamp}.txt`
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([bufferText()], { type: 'text/plain' }))
    a.download = name
    a.click()
    window.setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }

  const paneMenuItems = (): MenuItem[] => {
    const xterm = term.current
    return [
      {
        label: 'Copy',
        disabled: !xterm?.hasSelection(),
        onClick: () => void navigator.clipboard?.writeText(xterm?.getSelection() ?? ''),
      },
      { label: 'Paste', disabled: state !== 'live', onClick: pasteFromClipboard },
      { label: 'Select all', onClick: () => xterm?.selectAll() },
      MENU_BREAK,
      {
        label: 'Copy all output',
        onClick: () => {
          void navigator.clipboard?.writeText(bufferText())
            .then(() => say('info', 'The whole scrollback is on the clipboard.'))
            .catch(() => say('warning', 'The browser refused clipboard access.'))
        },
      },
      { label: 'Save output to a file', onClick: saveOutput },
      { label: 'Find in scrollback', onClick: () => setShowSearch(true) },
      MENU_BREAK,
      { label: 'Send a snippet…', disabled: !terminalId, onClick: () => setMenu('snippets') },
      { label: 'Broadcast to other terminals…', disabled: !terminalId, onClick: () => setMenu('broadcast') },
      {
        label: recorded ? 'Stop recording' : 'Start recording',
        disabled: !terminalId || recBusy || (recorded && forced),
        onClick: () => void toggleRecording(),
      },
      MENU_BREAK,
      { label: 'Bigger text', onClick: () => setZoom((z) => z + 1) },
      { label: 'Smaller text', onClick: () => setZoom((z) => z - 1) },
      { label: 'Normal text size', disabled: zoom === 0, onClick: () => setZoom(0) },
      { label: document.fullscreenElement ? 'Leave full screen' : 'Full screen', onClick: toggleFullscreen },
      MENU_BREAK,
      { label: 'Clear scrollback', onClick: () => xterm?.clear() },
      {
        label: 'Reset the terminal',
        onClick: () => {
          // A full reset is what rescues a screen a binary cat has left in
          // line-drawing mode. The host is unaffected; only the emulator is.
          xterm?.reset()
          say('info', 'Terminal reset. Press Enter for a fresh prompt.')
        },
      },
      ...(state === 'ended' && canReconnect
        ? [MENU_BREAK, { label: 'Reconnect', onClick: reconnect }]
        : []),
    ]
  }

  // What the menu bar and the window's status bar reach through the pane
  // handle. Refreshed every render, so it always reads the current state.
  const verbs = useRef<{
    copy: () => void
    reset: () => void
    saveOutput: () => void
    toggleRecording: () => void
    reconnect: () => boolean
    info: () => PaneInfo
  }>(null!)
  verbs.current = {
    copy: () => {
      const selection = term.current?.getSelection()
      if (selection) void navigator.clipboard?.writeText(selection)
      term.current?.focus()
    },
    reset: () => {
      term.current?.reset()
      term.current?.focus()
      say('info', 'Terminal reset. Press Enter for a fresh prompt.')
    },
    saveOutput,
    toggleRecording: () => void toggleRecording(),
    reconnect: () => {
      if (state !== 'ended' || !canReconnect) return false
      reconnect()
      return true
    },
    info: () => ({
      state,
      cols: dims?.cols ?? 0,
      rows: dims?.rows ?? 0,
      recorded,
      linesBack,
      zoomedSize: zoom !== 0 ? effectiveSize : null,
    }),
  }

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

  const screenBackground = THEMES[props.theme]?.background ?? '#0b0f14'

  return (
    <div
      ref={root}
      className={'pane' + (ringing ? ' ringing' : '') + (props.compact ? ' compact' : '')}
      data-testid="terminal-pane"
      data-pane-key={props.paneKey}
      data-state={state}
    >
      <div className="pane-status" role="status"
           hidden={props.compact && state === 'live' && !recorded && group.length === 0}>
        <StatusPill state={state} detail={detail} />
        {!props.compact && <span className="pane-label">{props.label}</span>}
        {countdown !== null && (
          <span className="countdown">
            reconnecting in {countdown}s
            <button className="link" onClick={reconnect}>now</button>
            <button className="link" onClick={stopCountdown}>cancel</button>
          </span>
        )}
        {state === 'ended' && canReconnect && countdown === null && (
          <button className="link" onClick={reconnect}>Reconnect</button>
        )}
        {linesBack > 0 && (
          <button className="link lines-back"
                  title="Jump back to the live end of the scrollback"
                  onClick={() => term.current?.scrollToBottom()}>
            {linesBack} lines up {'↓'}
          </button>
        )}
        {zoom !== 0 && (
          <button className="link zoom-badge" title="Text size in this pane; click to reset"
                  onClick={() => setZoom(0)}>
            {effectiveSize}px
          </button>
        )}
        {recorded && (
          <span className="rec-light" title={forced
            ? 'Recording is required by this server’s policy'
            : 'Output is being written to a transcript. Stop it from the menu.'}>
            <span className="rec-dot" />
            REC
          </span>
        )}
        {group.length > 0 && (
          <span className="tag warn-tag" data-testid="broadcast-badge">
            typing into {group.length + 1}
          </span>
        )}
        <div className="pane-tools">
          <button
            className="link pane-more"
            aria-label="More terminal actions"
            title="Copy, paste, find, snippets, broadcast, recording, text size…"
            onClick={(e) => {
              const r = (e.currentTarget as HTMLElement).getBoundingClientRect()
              setPaneMenu({ x: r.right - 220, y: r.bottom + 4 })
            }}
          >
            {'⋯'}
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

      {sending && (
        <div className="pane-sending" role="status">
          <span>Pasting line {sending.done + 1} of {sending.total}</span>
          <progress max={sending.total} value={sending.done} />
          <button className="link" onClick={cancelSending}>Stop</button>
        </div>
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

      <div className="pane-screen" ref={host} style={{ background: screenBackground }} />

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

      {failure && !changed && countdown === null && (
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
              Paste {pendingPaste.replace(/[\r\n]+$/, '').split('\n').length} lines
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
            {/*
              Editable, like SecureCRT's: the dialog is a last chance to trim
              the interface names that came along with the copy, not just a
              speed bump to click through.
            */}
            <textarea
              className="paste-preview"
              aria-label="The text about to be pasted"
              value={pendingPaste}
              onChange={(e) => setPendingPaste(e.target.value)}
            />
            <form
              className="row paste-actions"
              onSubmit={(e) => {
                e.preventDefault()
                const delay = Math.max(0, Math.min(5000, Number(pasteDelay) || 0))
                sendPaste(pendingPaste, delay)
                setPendingPaste(null)
                term.current?.focus()
              }}
            >
              <button type="submit" className="primary" autoFocus>Paste</button>
              <button type="button" onClick={() => { setPendingPaste(null); term.current?.focus() }}>
                Cancel
              </button>
              <label className="inline paste-delay"
                     title="Wait between lines, for consoles that drop characters">
                Line delay
                <input inputMode="numeric" value={pasteDelay}
                       onChange={(e) => setPasteDelay(e.target.value.replace(/\D/g, ''))} />
                ms
              </label>
            </form>
          </div>
        </div>
      )}

      {paneMenu && (
        <ContextMenu
          x={paneMenu.x}
          y={paneMenu.y}
          items={paneMenuItems()}
          onClose={() => { setPaneMenu(null); term.current?.focus() }}
        />
      )}
    </div>
  )
}

/** needsGate says whether a paste is more than one line. */
function needsGate(text: string): boolean {
  return /[\r\n]/.test(text.replace(/[\r\n]+$/, ''))
}

/** A short, quiet beep, for people who asked for an audible bell. */
let audio: AudioContext | null = null
function beep() {
  try {
    audio ??= new AudioContext()
    const osc = audio.createOscillator()
    const gain = audio.createGain()
    osc.frequency.value = 880
    gain.gain.setValueAtTime(0.06, audio.currentTime)
    gain.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + 0.12)
    osc.connect(gain).connect(audio.destination)
    osc.start()
    osc.stop(audio.currentTime + 0.13)
  } catch {
    // No audio device, or autoplay policy said no. A silent bell is still a bell.
  }
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
