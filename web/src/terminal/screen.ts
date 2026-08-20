import type { Terminal } from '@xterm/xterm'
import type { DrawnSpan, Highlighter } from './highlight'

/**
 * A registry of open terminals, exposed on `window` for the browser suite.
 *
 * This is a deliberate test seam, and it exists because there is no
 * alternative. The WebGL renderer draws the terminal to a canvas, so its
 * contents live in no DOM node a test could query — without this, a browser
 * test could prove that pixels were painted but not what they said, which is
 * precisely the thing worth proving.
 *
 * It reveals nothing the page does not already hold: same origin, same tab,
 * the user's own screen. It reads the scrollback buffer and cannot write to
 * it, so it offers no way to type into a session.
 */
const open = new Map<string, Terminal>()
const highlighters = new Map<string, Highlighter>()

export function registerTerminal(key: string, term: Terminal): void {
  open.set(key, term)
}

export function unregisterTerminal(key: string): void {
  open.delete(key)
  highlighters.delete(key)
}

/**
 * registerHighlighter exposes what keyword highlighting marked.
 *
 * Same reasoning as the screen text, and more sharply: a decoration with a
 * background colour is painted into the canvas by the renderer, so it leaves
 * no DOM node at all. Without this a browser test could prove the terminal
 * still worked with rules loaded and nothing more.
 */
export function registerHighlighter(key: string, highlighter: Highlighter): void {
  highlighters.set(key, highlighter)
}

/** readScreen returns the scrollback and viewport of one terminal as text. */
function readScreen(term: Terminal): string {
  const buffer = term.buffer.active
  const lines: string[] = []
  for (let i = 0; i < buffer.length; i++) {
    // trimRight: xterm pads every line to the full width, and trailing
    // spaces would defeat any assertion anchored to the end of a line.
    lines.push(buffer.getLine(i)?.translateToString(true) ?? '')
  }
  return lines.join('\n')
}

declare global {
  interface Window {
    bkdTerminalText?: (key: string) => string | null
    bkdTerminalHighlights?: (key: string) => DrawnSpan[] | null
  }
}

if (typeof window !== 'undefined') {
  window.bkdTerminalText = (key: string) => {
    const term = open.get(key)
    return term ? readScreen(term) : null
  }
  window.bkdTerminalHighlights = (key: string) => {
    const highlighter = highlighters.get(key)
    return highlighter ? highlighter.drawn() : null
  }
}
