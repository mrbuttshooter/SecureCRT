// TerminalSocket speaks the terminal wire protocol to the server.
//
// The protocol is deliberately thin — binary frames are raw terminal bytes,
// text frames are JSON control messages — so most of what lives here is not
// framing but the part that makes a web terminal feel like a native one:
// noticing a dropped connection and getting back to the same shell.
//
// The SSH session belongs to the server. A dropped socket does not end it, so
// reconnecting means reattaching by terminal ID and letting the server replay
// the recent scrollback, not dialling the host again.

export type ControlType =
  | 'resize' | 'host_key_decision' | 'broadcast' | 'ping'
  | 'status' | 'host_key_prompt' | 'host_key_changed'
  | 'warning' | 'trigger' | 'error' | 'closed' | 'pong'

export type ConnectStatus =
  | 'dialling' | 'verifying_host' | 'authenticating' | 'connected' | 'reattached'

export interface HostKeyInfo {
  hostname: string
  port: number
  key_type: string
  fingerprint: string
  previous_fingerprint?: string
  previously_seen?: string
  org_wide?: boolean
}

/** One keyword-highlighting rule, drawn here rather than on the server. */
export interface HighlightRule {
  name: string
  pattern: string
  colour?: string
}

/** TriggerEvent is one of the user's rules firing. Never carries what it sent. */
export interface TriggerEvent {
  name: string
  action: 'send' | 'notify' | 'highlight' | 'stop'
  line: string
  colour?: string
}

export interface Control {
  type: ControlType
  cols?: number
  rows?: number
  status?: ConnectStatus
  message?: string
  code?: string
  host_key?: HostKeyInfo
  accepted?: boolean
  terminal_id?: string
  exit_status?: number
  highlights?: HighlightRule[]
  trigger?: TriggerEvent
  terminals?: string[]
}

/** How the socket is doing, as far as the interface needs to care. */
export type LinkState =
  | 'opening'      // the WebSocket is being established
  | 'connecting'   // open, and the server is dialling the host
  | 'prompting'    // waiting on a host key decision
  | 'live'         // bytes are flowing
  | 'reconnecting' // dropped, and trying to reattach
  | 'ended'        // the remote session finished, or we gave up

export interface TerminalSocketHandlers {
  onData: (bytes: Uint8Array) => void
  onState: (state: LinkState, detail?: string) => void
  onHostKeyPrompt: (info: HostKeyInfo) => void
  onHostKeyChanged: (info: HostKeyInfo, message: string) => void
  onError: (code: string, message: string) => void
  onTerminalID: (id: string) => void
  onClosed: (exitStatus?: number) => void

  /**
   * onHighlights carries the colouring rules, on every attach.
   *
   * Sent again after a reconnect rather than once at the start, because the
   * browser holds nothing across a dropped socket and a long-running session
   * is exactly the one whose network has had time to blink.
   */
  onHighlights: (rules: HighlightRule[]) => void

  /** onTrigger reports one of the user's watch rules firing. */
  onTrigger: (event: TriggerEvent) => void

  /** onWarning is something worth saying that did not stop the terminal. */
  onWarning: (code: string, message: string) => void

  /** onBroadcast acknowledges the terminals this keyboard now also reaches. */
  onBroadcast: (terminals: string[]) => void
}

/**
 * How long to wait before each reconnection attempt.
 *
 * The first is immediate, because much the commonest cause of a dropped
 * socket is a momentary network blip and an instant retry makes it invisible.
 * After that it backs off, so a server that is genuinely down is not hammered
 * by every open tab in the building.
 */
const RECONNECT_DELAYS_MS = [0, 1_000, 2_000, 5_000, 10_000, 15_000, 30_000]

/**
 * How often to send an application-level ping.
 *
 * The WebSocket layer has its own, but that only proves the socket is open.
 * This one traverses the whole path, so a wedged SSH session shows up as a
 * missing pong rather than as a terminal that silently stops responding.
 */
const PING_INTERVAL_MS = 30_000

export interface OpenParams {
  /** Saved connection to dial. Mutually exclusive with terminalId. */
  sessionId?: string
  /** Existing server-side terminal to reattach to. */
  terminalId?: string
  cols: number
  rows: number
}

export class TerminalSocket {
  private ws: WebSocket | null = null
  private readonly handlers: TerminalSocketHandlers
  private params: OpenParams
  private terminalId: string | null = null
  private attempt = 0
  private reconnectTimer: number | null = null
  private pingTimer: number | null = null
  private closedByUs = false
  private lastSize: { cols: number; rows: number }

  constructor(params: OpenParams, handlers: TerminalSocketHandlers) {
    this.params = params
    this.handlers = handlers
    this.lastSize = { cols: params.cols, rows: params.rows }
    if (params.terminalId) this.terminalId = params.terminalId
  }

  /** id is the server-side terminal, once the server has told us one. */
  get id(): string | null {
    return this.terminalId
  }

  open(): void {
    this.closedByUs = false
    this.connect()
  }

  /** close ends the socket. The server-side terminal keeps running. */
  close(): void {
    this.closedByUs = true
    this.clearTimers()
    this.ws?.close(1000, 'closed by the user')
    this.ws = null
  }

  send(data: string | Uint8Array): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    // Node's WebSocket types are stricter than the DOM's about the buffer
    // flavour; the copy costs nothing at keystroke sizes.
    this.ws.send(typeof data === 'string' ? data : new Uint8Array(data).slice().buffer)
  }

  resize(cols: number, rows: number): void {
    if (cols === this.lastSize.cols && rows === this.lastSize.rows) return
    this.lastSize = { cols, rows }
    this.params = { ...this.params, cols, rows }
    this.control({ type: 'resize', cols, rows })
  }

  /** answerHostKey resolves a pending host key prompt. */
  answerHostKey(accepted: boolean): void {
    this.control({ type: 'host_key_decision', accepted })
  }

  /**
   * broadcast puts this keyboard onto several terminals, or — with an empty
   * list — takes it off them.
   *
   * The fan-out happens on the server. Writing to several sockets from here
   * would put the "may this person type into that terminal" check in the
   * browser, which is not a check at all.
   */
  broadcast(terminals: string[]): void {
    this.control({ type: 'broadcast', terminals })
  }

  private control(msg: Control): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(msg))
  }

  private url(): string {
    const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const query = new URLSearchParams({
      cols: String(this.lastSize.cols),
      rows: String(this.lastSize.rows),
    })
    // Reattach wins over dial: once a terminal exists, reconnecting must
    // return to it rather than opening a second session on the same host.
    if (this.terminalId) query.set('terminal', this.terminalId)
    else if (this.params.sessionId) query.set('session', this.params.sessionId)

    return `${scheme}//${window.location.host}/api/terminals/socket?${query}`
  }

  private connect(): void {
    this.clearTimers()
    this.handlers.onState(this.terminalId && this.attempt > 0 ? 'reconnecting' : 'opening')

    let ws: WebSocket
    try {
      ws = new WebSocket(this.url())
    } catch {
      this.scheduleReconnect()
      return
    }
    ws.binaryType = 'arraybuffer'
    this.ws = ws

    ws.onopen = () => {
      this.attempt = 0
      this.handlers.onState(this.terminalId ? 'live' : 'connecting')
      this.startPings()
      // Reattaching to a terminal whose window changed size while we were
      // away: tell the server before the first keystroke, so the shell does
      // not redraw against stale dimensions.
      if (this.terminalId) this.control({ type: 'resize', ...this.lastSize })
    }

    ws.onmessage = (event: MessageEvent) => {
      if (typeof event.data === 'string') {
        this.handleControl(event.data)
        return
      }
      this.handlers.onData(new Uint8Array(event.data as ArrayBuffer))
    }

    ws.onerror = () => {
      // Nothing useful is exposed on a WebSocket error event by design; the
      // close event that follows carries what there is.
    }

    ws.onclose = () => {
      this.clearTimers()
      this.ws = null
      if (this.closedByUs) return

      // Without a terminal ID there is nothing to reattach to: the failure
      // happened before the session existed, so retrying would just re-dial
      // a host that already refused us.
      if (!this.terminalId) {
        this.handlers.onState('ended')
        return
      }
      this.scheduleReconnect()
    }
  }

  private handleControl(raw: string): void {
    let msg: Control
    try {
      msg = JSON.parse(raw) as Control
    } catch {
      return
    }

    switch (msg.type) {
      case 'status':
        if (msg.terminal_id) this.adoptTerminalID(msg.terminal_id)
        if (msg.highlights) this.handlers.onHighlights(msg.highlights)
        if (msg.status === 'connected' || msg.status === 'reattached') {
          this.handlers.onState('live')
        } else {
          this.handlers.onState('connecting', msg.status)
        }
        break

      case 'trigger':
        if (msg.trigger) this.handlers.onTrigger(msg.trigger)
        break

      case 'warning':
        this.handlers.onWarning(msg.code ?? 'warning', msg.message ?? '')
        break

      case 'broadcast':
        this.handlers.onBroadcast(msg.terminals ?? [])
        break

      case 'host_key_prompt':
        this.handlers.onState('prompting')
        if (msg.host_key) this.handlers.onHostKeyPrompt(msg.host_key)
        break

      case 'host_key_changed':
        this.closedByUs = true // there is no answer that continues
        this.handlers.onState('ended')
        if (msg.host_key) {
          this.handlers.onHostKeyChanged(msg.host_key, msg.message ?? 'The host key has changed.')
        }
        break

      case 'error':
        // A failure the server reports is final for this attempt; retrying
        // would repeat it. Reconnection exists for dropped sockets, not for
        // refusals.
        this.closedByUs = true
        this.handlers.onState('ended')
        this.handlers.onError(msg.code ?? 'internal_error', msg.message ?? 'The connection failed.')
        break

      case 'closed':
        this.closedByUs = true
        this.handlers.onState('ended')
        this.handlers.onClosed(msg.exit_status)
        break

      case 'pong':
        break
    }

    if (msg.terminal_id) this.adoptTerminalID(msg.terminal_id)
  }

  private adoptTerminalID(id: string): void {
    if (this.terminalId === id) return
    this.terminalId = id
    this.handlers.onTerminalID(id)
  }

  private scheduleReconnect(): void {
    const delay = RECONNECT_DELAYS_MS[Math.min(this.attempt, RECONNECT_DELAYS_MS.length - 1)]
    this.attempt += 1
    this.handlers.onState('reconnecting')
    this.reconnectTimer = window.setTimeout(() => this.connect(), delay)
  }

  private startPings(): void {
    this.pingTimer = window.setInterval(() => this.control({ type: 'ping' }), PING_INTERVAL_MS)
  }

  private clearTimers(): void {
    if (this.reconnectTimer !== null) window.clearTimeout(this.reconnectTimer)
    if (this.pingTimer !== null) window.clearInterval(this.pingTimer)
    this.reconnectTimer = null
    this.pingTimer = null
  }
}
