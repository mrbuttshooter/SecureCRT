/**
 * Handles onto the open panes, for the parts of the workspace that act on a
 * terminal without being inside it — the command window, the session finder.
 *
 * Everything sent through a handle goes down that pane's own socket, the same
 * path as a keystroke. So a pane that is broadcasting fans it out on the
 * server, which re-checks every target, exactly as it would for typing; this
 * registry never decides on its own which terminals receive what.
 */
export interface PaneHandle {
  /** Type text as if from the keyboard. */
  type: (text: string) => void
  /**
   * Paste text, through the paste guard and the line delay. True if it went
   * out now; false if it waits on the confirmation or was refused.
   */
  paste: (text: string) => boolean
  focus: () => void
  /** Whether the session is up and accepting input. */
  live: () => boolean
  /** How many terminals the keyboard reaches, this one included. */
  reach: () => number
  /** Text size in this pane: one step up or down, or 0 to reset. */
  zoom: (step: 1 | -1 | 0) => void
  fullscreen: () => void
  find: () => void
  /** Open or close the broadcast picker. */
  broadcastMenu: () => void
  /** Open or close the snippet picker. */
  snippetsMenu: () => void

  // Edit-menu verbs, so the menu bar and toolbar can act on the pane in front.
  copy: () => void
  pasteClipboard: () => void
  selectAll: () => void
  clear: () => void
  reset: () => void
  saveOutput: () => void
  toggleRecording: () => void
  /** Redial an ended session in place; false if there is nothing to redial. */
  reconnect: () => boolean

  /** What the status bar shows about this pane. */
  info: () => PaneInfo
}

export interface PaneInfo {
  state: string
  cols: number
  rows: number
  recorded: boolean
  linesBack: number
  zoomedSize: number | null
}

const panes = new Map<string, PaneHandle>()

export function registerPane(key: string, handle: PaneHandle): void {
  panes.set(key, handle)
}

export function unregisterPane(key: string): void {
  panes.delete(key)
}

export function paneHandle(key: string | null | undefined): PaneHandle | undefined {
  return key ? panes.get(key) : undefined
}
