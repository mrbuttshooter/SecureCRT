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

/** commandFor maps a keydown to an app command, or null to leave it alone. */
export function commandFor(event: KeyboardEvent): AppCommand | null {
  if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
    if (event.key >= '1' && event.key <= '9') {
      return { kind: 'jump', index: Number(event.key) - 1 }
    }
    if (event.key === 'PageDown') return { kind: 'next-tab' }
    if (event.key === 'PageUp') return { kind: 'prev-tab' }
    return null
  }

  if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey) {
    // event.key is affected by shift; event.code names the physical key.
    switch (event.code) {
      case 'KeyQ': return { kind: 'quick-connect' }
      case 'KeyX': return { kind: 'close-tab' }
      case 'KeyD': return { kind: 'duplicate-tab' }
      case 'KeyF': return { kind: 'find' }
      case 'KeyB': return { kind: 'broadcast' }
      // The SecureCRT reflex: jump to the session filter and type part of a
      // hostname. Their Alt+K, our Ctrl+Shift+K.
      case 'KeyK': return { kind: 'filter' }
    }
  }

  return null
}
