/**
 * The keyboard map, in one place.
 *
 * The browser owns Ctrl+T, Ctrl+W, Ctrl+Tab, Ctrl+1..9 and friends — those
 * chords never reach the page, so pretending to bind them would produce a
 * shortcut sheet full of lies. What is bindable, and what this uses:
 *
 *   Alt+1..9            jump to tab N (readline uses Alt+digit only for
 *                       numeric arguments, which almost nobody types)
 *   Alt+PageUp/PageDown previous / next tab
 *   Ctrl+Shift+Q        quick connect
 *   Ctrl+Shift+X        close the active tab
 *   Ctrl+Shift+D        duplicate the active tab
 *   Ctrl+Shift+F        find in scrollback (per pane)
 *   Ctrl+Shift+B        broadcast menu (per pane)
 *   Ctrl+Shift+K        focus the connection filter
 *   Ctrl+Shift+Space    find a connection or an open tab by typing
 *   Ctrl+Shift+Enter    show or hide the command window
 *   Ctrl+Shift+L        cycle the layout: one, two side by side, tiled
 *   Ctrl+Shift+,        terminal settings
 *   Ctrl+Shift+/        this list, on screen
 *   Ctrl+Shift+= / -    bigger / smaller text in this pane; Ctrl+Shift+0 resets
 *   Alt+Enter           this pane full screen (SecureCRT's own binding)
 *
 * Ctrl+Shift+M, O and P were considered and left alone: browsers bind them to
 * a profile menu, a bookmarks window and private browsing, and some refuse to
 * let a page have them back.
 *
 * Alt+<letter> is left strictly alone: xterm sends it as an ESC-prefixed
 * sequence, and Alt+B / Alt+F / Alt+. are readline muscle memory that a
 * terminal product must never steal.
 *
 * Every binding is claimed in two places: the workspace's document listener
 * (so it works when focus is anywhere) and each pane's
 * attachCustomKeyEventHandler (so xterm does not also forward the chord to
 * the remote host — a document listener alone would run *in addition to*
 * xterm's handling, and the switch would receive the keystroke too).
 */

export type AppCommand =
  | { kind: 'jump'; index: number }
  | { kind: 'next-tab' }
  | { kind: 'prev-tab' }
  | { kind: 'quick-connect' }
  | { kind: 'close-tab' }
  | { kind: 'duplicate-tab' }
  | { kind: 'find' }
  | { kind: 'broadcast' }
  | { kind: 'filter' }
  | { kind: 'finder' }
  | { kind: 'command-window' }
  | { kind: 'layout' }
  | { kind: 'settings' }
  | { kind: 'shortcuts' }
  | { kind: 'fullscreen' }
  | { kind: 'zoom'; step: 1 | -1 | 0 }

/** Which commands act on the focused pane rather than on the workspace. */
export const PANE_COMMANDS: ReadonlySet<AppCommand['kind']> = new Set(['find', 'broadcast', 'zoom', 'fullscreen'])

/**
 * The shortcut sheet, in the order a newcomer wants to learn them. Kept next
 * to commandFor so the two cannot drift apart without it being obvious.
 */
export const SHORTCUTS: ReadonlyArray<[string, string]> = [
  ['Ctrl+Shift+Space', 'Find a connection or open tab'],
  ['Ctrl+Shift+Q', 'Quick connect'],
  ['Ctrl+Shift+K', 'Filter the connection tree'],
  ['Alt+1 … Alt+9', 'Jump to tab'],
  ['Alt+PgUp / Alt+PgDn', 'Previous / next tab'],
  ['Ctrl+Shift+D', 'Duplicate this tab'],
  ['Ctrl+Shift+X', 'Close this tab'],
  ['Ctrl+Shift+L', 'Cycle layout: single, split, tiled'],
  ['Alt+Enter', 'This pane full screen'],
  ['Ctrl+Shift+F', 'Find in scrollback'],
  ['Ctrl+Shift+B', 'Broadcast to other terminals'],
  ['Ctrl+Shift+Enter', 'Command window'],
  ['Ctrl+Shift+= / − / 0', 'Text size in this pane'],
  ['Ctrl+wheel', 'Text size in this pane'],
  ['Enter (ended pane)', 'Reconnect'],
  ['Select / right-click', 'Copy / paste'],
  ['Ctrl+Shift+,', 'Terminal settings'],
  ['Ctrl+Shift+/', 'This list'],
]

const KEY_CODES: Record<string, string> = {
  ',': 'Comma', '<': 'Comma', '/': 'Slash', '?': 'Slash',
  '=': 'Equal', '+': 'Equal', '-': 'Minus', '_': 'Minus',
  ' ': 'Space', '0': 'Digit0', ')': 'Digit0', Enter: 'Enter',
}

function codeFromKey(key: string): string {
  if (/^[a-z]$/i.test(key)) return 'Key' + key.toUpperCase()
  return KEY_CODES[key] ?? ''
}

/** commandFor maps a keydown to an app command, or null to leave it alone. */
export function commandFor(event: KeyboardEvent): AppCommand | null {
  if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
    if (event.key >= '1' && event.key <= '9') {
      return { kind: 'jump', index: Number(event.key) - 1 }
    }
    if (event.key === 'PageDown') return { kind: 'next-tab' }
    if (event.key === 'PageUp') return { kind: 'prev-tab' }
    if (event.key === 'Enter') return { kind: 'fullscreen' }
    return null
  }

  if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey) {
    // event.key is affected by shift; event.code names the physical key.
    // Some remote-desktop clients and synthetic events leave code empty, so
    // fall back to what the key produced.
    switch (event.code || codeFromKey(event.key)) {
      case 'KeyQ': return { kind: 'quick-connect' }
      case 'KeyX': return { kind: 'close-tab' }
      case 'KeyD': return { kind: 'duplicate-tab' }
      case 'KeyF': return { kind: 'find' }
      case 'KeyB': return { kind: 'broadcast' }
      // The SecureCRT reflex: jump to the session filter and type part of a
      // hostname. Their Alt+K, our Ctrl+Shift+K.
      case 'KeyK': return { kind: 'filter' }
      case 'Space': return { kind: 'finder' }
      case 'Enter':
      case 'NumpadEnter': return { kind: 'command-window' }
      case 'KeyL': return { kind: 'layout' }
      case 'Comma': return { kind: 'settings' }
      case 'Slash': return { kind: 'shortcuts' }
      case 'Equal':
      case 'NumpadAdd': return { kind: 'zoom', step: 1 }
      case 'Minus':
      case 'NumpadSubtract': return { kind: 'zoom', step: -1 }
      case 'Digit0':
      case 'Numpad0': return { kind: 'zoom', step: 0 }
    }
  }

  return null
}
