import type { IMarker, Terminal } from '@xterm/xterm'

// Keyword highlighting: marking the lines that matter as they scroll past.
//
// The point of it is a 10,000-line scrollback. Nobody reads that; they scan it
// for the four lines that say something went wrong, and colour is what turns
// scanning into seeing. That is also why every match leaves a mark in the
// overview ruler down the right-hand edge — the scrollbar becomes a map of
// where the errors are, so finding them does not mean scrolling through
// everything that was fine.
//
// # Where the matching happens, and why it is not here
//
// The rules are regular expressions. On the server they run under RE2, which
// is linear-time by construction; in a browser they run under a backtracking
// engine, where a pattern that RE2 executes in microseconds can take longer
// than the heat death of the sun and cannot be interrupted, because it never
// yields. A frozen tab with a live SSH session behind it is a bad outcome for
// a cosmetic feature.
//
// So matching happens in a worker with a deadline, and a worker that misses
// its deadline is terminated. Highlighting then stops for that pane and says
// so. It is the only mechanism a browser offers that actually bounds this.

/** One rule as the server sends it. */
export interface HighlightRule {
  name: string
  pattern: string
  colour?: string
}

/**
 * How long the worker gets to answer before it is assumed wedged.
 *
 * Generous — a batch is at most a few hundred short lines and takes under a
 * millisecond — because the cost of being wrong is throwing away somebody's
 * highlighting, and the thing being caught is not slow but unbounded.
 */
const SCAN_TIMEOUT_MS = 2_000

/** How long lines accumulate before a batch is sent. */
const BATCH_MS = 40

/**
 * How many lines may wait to be scanned.
 *
 * A `cat` of a large file produces lines far faster than anything can colour
 * them, and a queue that grew to match would hold a marker per line and a
 * copy of the text. Beyond this the oldest are dropped: highlighting is
 * cosmetic, and dropping it during a flood is the right way to fail.
 */
const MAX_PENDING = 400

interface PendingLine {
  key: number
  text: string
  marker: IMarker
}

interface Span {
  key: number
  x: number
  width: number
  colour: string
  rule: string
}

/**
 * The palette, by name.
 *
 * Trigger colours are free text, so this is a set of names the interface
 * offers rather than an enumeration anything enforces. Backgrounds are dark
 * and foregrounds are set explicitly, so a highlight reads the same against
 * every terminal theme instead of vanishing into a pale one.
 */
const PALETTE: Record<string, { background: string; foreground: string }> = {
  red: { background: '#7f1d1d', foreground: '#fee2e2' },
  orange: { background: '#7c2d12', foreground: '#ffedd5' },
  amber: { background: '#78350f', foreground: '#fef3c7' },
  yellow: { background: '#713f12', foreground: '#fef9c3' },
  green: { background: '#14532d', foreground: '#dcfce7' },
  teal: { background: '#134e4a', foreground: '#ccfbf1' },
  cyan: { background: '#164e63', foreground: '#cffafe' },
  blue: { background: '#1e3a8a', foreground: '#dbeafe' },
  purple: { background: '#4c1d95', foreground: '#ede9fe' },
  magenta: { background: '#701a75', foreground: '#fae8ff' },
  grey: { background: '#374151', foreground: '#f3f4f6' },
}

/** COLOUR_NAMES is the palette in the order the editor offers it. */
export const COLOUR_NAMES = Object.keys(PALETTE)

const DEFAULT_COLOUR = PALETTE.amber!

/** colourFor resolves a rule's colour, accepting a hex value as written. */
function colourFor(name: string | undefined): { background: string; foreground: string } {
  if (!name) return DEFAULT_COLOUR

  const known = PALETTE[name.toLowerCase()]
  if (known) return known

  // A hex colour somebody typed in. xterm takes #RRGGBB only, so anything
  // else falls back rather than being passed through to be ignored.
  if (/^#[0-9a-f]{6}$/i.test(name)) {
    return { background: name, foreground: readableOn(name) }
  }
  return DEFAULT_COLOUR
}

/** readableOn picks black or white text for a background. */
function readableOn(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  // Rec. 601 luma, which is close enough for deciding between two options.
  return (r * 299 + g * 587 + b * 114) / 1000 > 140 ? '#111827' : '#f9fafb'
}

/** DrawnSpan is one mark that was made, for the browser suite. */
export interface DrawnSpan {
  rule: string
  colour: string
  text: string
}

/**
 * How many marks are remembered for the test seam.
 *
 * Bounded because it is a debugging aid on a session that may run for days,
 * not a log. The suite asserts on the most recent ones.
 */
const REMEMBERED_SPANS = 200

export interface HighlighterEvents {
  /** Something the user should know: a refused rule, or matching giving up. */
  onNotice: (message: string) => void
}

/**
 * Highlighter colours a terminal's output as it arrives.
 *
 * One per pane, created with the pane and disposed with it. Rules arrive from
 * the server on every attach, so `setRules` is called again after a reconnect
 * rather than only once.
 */
export class Highlighter {
  private readonly term: Terminal
  private readonly events: HighlighterEvents

  private worker: Worker | null = null
  private rules: HighlightRule[] = []
  private stopped = false

  private pending: PendingLine[] = []
  private inFlight = new Map<number, PendingLine>()
  private nextKey = 0
  private batch = 0

  private flushTimer: number | null = null
  private deadline: number | null = null

  private lineFeed: { dispose(): void } | null = null

  /** drawn is the recent marks, for the browser suite. See screen.ts. */
  private readonly drawnSpans: DrawnSpan[] = []

  constructor(term: Terminal, events: HighlighterEvents) {
    this.term = term
    this.events = events
  }

  /**
   * setRules installs the rules the server sent.
   *
   * Replacing them restarts the worker: a rule that was terminated for
   * overrunning must get another chance once it has been edited, and the
   * only signal that it has been is a fresh set arriving.
   */
  setRules(rules: HighlightRule[]): void {
    this.rules = rules
    this.stopped = false
    this.teardownWorker()
    this.discardPending()

    if (rules.length === 0) {
      this.lineFeed?.dispose()
      this.lineFeed = null
      return
    }

    if (!this.startWorker()) return

    if (!this.lineFeed) {
      // onLineFeed rather than a write hook, because a line is only worth
      // matching once it is finished — and it is finished exactly when the
      // cursor leaves it. Watching writes instead would re-match a progress
      // bar redrawing itself sixty times a second.
      this.lineFeed = this.term.onLineFeed(() => this.captureCompletedLine())
    }
  }

  /** drawn returns the marks made recently, newest last. */
  drawn(): DrawnSpan[] {
    return this.drawnSpans.slice()
  }

  /** dispose releases the worker, the timers and every outstanding marker. */
  dispose(): void {
    this.lineFeed?.dispose()
    this.lineFeed = null
    this.teardownWorker()
    this.discardPending()
  }

  private startWorker(): boolean {
    try {
      this.worker = new Worker(new URL('./highlight.worker.ts', import.meta.url), {
        type: 'module',
      })
    } catch {
      // No worker available. Highlighting is off rather than run on the main
      // thread, because the main thread is the one thing that must not stop.
      this.events.onNotice('Keyword highlighting is unavailable in this browser.')
      this.stopped = true
      return false
    }

    this.worker.onmessage = (event: MessageEvent) => this.receive(event.data)
    this.worker.onerror = () => this.giveUp('Keyword highlighting stopped: the matcher failed.')
    this.worker.postMessage({ type: 'rules', rules: this.rules })
    return true
  }

  private teardownWorker(): void {
    if (this.flushTimer !== null) {
      window.clearTimeout(this.flushTimer)
      this.flushTimer = null
    }
    if (this.deadline !== null) {
      window.clearTimeout(this.deadline)
      this.deadline = null
    }
    this.worker?.terminate()
    this.worker = null
    for (const line of this.inFlight.values()) line.marker.dispose()
    this.inFlight.clear()
  }

  private discardPending(): void {
    for (const line of this.pending) line.marker.dispose()
    this.pending = []
  }

  /** captureCompletedLine takes the line the cursor has just left. */
  private captureCompletedLine(): void {
    if (this.stopped || !this.worker) return

    const buffer = this.term.buffer.active
    const y = buffer.baseY + buffer.cursorY - 1
    if (y < 0) return

    const line = buffer.getLine(y)
    if (!line) return

    const text = line.translateToString(true)
    if (!text) return

    if (this.pending.length >= MAX_PENDING) {
      // Output is arriving faster than it can be coloured. The oldest goes,
      // because the newest is what somebody is watching.
      this.pending.shift()?.marker.dispose()
    }

    // The marker is taken now, while the line is still where it was read
    // from. By the time the worker answers the buffer will have scrolled, and
    // an offset computed then would land on a different line.
    const marker = this.term.registerMarker(-1)
    if (!marker) return

    this.pending.push({ key: this.nextKey++, text, marker })
    this.scheduleFlush()
  }

  private scheduleFlush(): void {
    if (this.flushTimer !== null || this.inFlight.size > 0) return
    this.flushTimer = window.setTimeout(() => {
      this.flushTimer = null
      this.flush()
    }, BATCH_MS)
  }

  private flush(): void {
    if (this.stopped || !this.worker || this.pending.length === 0) return

    const lines = this.pending
    this.pending = []
    this.batch++

    for (const line of lines) this.inFlight.set(line.key, line)

    // The deadline is the whole defence. A worker stuck in a backtracking
    // regular expression never answers and never yields, so the only way out
    // is to stop waiting and kill it.
    this.deadline = window.setTimeout(() => {
      this.deadline = null
      this.giveUp(
        'Keyword highlighting stopped: a rule took too long to match. ' +
          'Check the pattern in ' + this.rules.map((r) => `“${r.name}”`).join(', ') + '.',
      )
    }, SCAN_TIMEOUT_MS)

    this.worker.postMessage({
      type: 'scan',
      batch: this.batch,
      lines: lines.map((line) => ({ key: line.key, text: line.text })),
    })
  }

  private receive(message: { type: string; spans?: Span[]; rule?: string; reason?: string }): void {
    if (message.type === 'rejected') {
      this.events.onNotice(
        `The highlight rule “${message.rule}” could not be used here: ${message.reason}`,
      )
      return
    }
    if (message.type !== 'scanned') return

    if (this.deadline !== null) {
      window.clearTimeout(this.deadline)
      this.deadline = null
    }

    for (const span of message.spans ?? []) {
      const line = this.inFlight.get(span.key)
      if (!line) continue
      this.draw(line.marker, span)

      if (this.drawnSpans.length >= REMEMBERED_SPANS) this.drawnSpans.shift()
      this.drawnSpans.push({
        rule: span.rule,
        colour: span.colour,
        text: line.text.slice(span.x, span.x + span.width),
      })
    }

    // Markers with no matches are disposed; the ones carrying a decoration
    // are held by it and go when the line leaves the scrollback.
    for (const line of this.inFlight.values()) {
      if (!(message.spans ?? []).some((span) => span.key === line.key)) line.marker.dispose()
    }
    this.inFlight.clear()

    if (this.pending.length > 0) this.scheduleFlush()
  }

  private draw(marker: IMarker, span: Span): void {
    const colour = colourFor(span.colour)
    this.term.registerDecoration({
      marker,
      x: span.x,
      width: span.width,
      backgroundColor: colour.background,
      foregroundColor: colour.foreground,
      layer: 'bottom',
      // The mark in the ruler is what makes a long scrollback searchable by
      // eye: the scrollbar shows where the matches are without scrolling.
      overviewRulerOptions: { color: colour.background, position: 'right' },
    })
  }

  private giveUp(message: string): void {
    this.stopped = true
    this.teardownWorker()
    this.discardPending()
    this.events.onNotice(message)
  }
}
