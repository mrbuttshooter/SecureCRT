import { FONT_FAMILIES, isThemeName, type ThemeName } from './themes'

/**
 * Terminal preferences: this browser's choices about how terminals look and
 * behave. Local by design — they describe a screen and a pair of hands, not
 * a device, so they belong to the browser rather than to the server. What a
 * device should look like (production is red) is a property of the saved
 * connection instead, and wins over these where it is set.
 */

/** How many terminals are on screen at once. */
export type Layout = 'single' | 'split' | 'grid'

/** What a terminal bell (^G) does. */
export type BellMode = 'visual' | 'sound' | 'none'

export type CursorStyle = 'block' | 'bar' | 'underline'

export interface Prefs {
  theme: ThemeName
  fontSize: number
  /** A key of FONT_FAMILIES. */
  fontFamily: string
  scrollback: number
  cursorStyle: CursorStyle
  cursorBlink: boolean

  /** Selecting text copies it, as in PuTTY and SecureCRT. */
  copyOnSelect: boolean
  /** Right-click pastes rather than opening a menu. */
  rightClickPaste: boolean
  /** Ask before pasting more than one line into a terminal. */
  pasteGuard: boolean
  /**
   * Milliseconds between lines when a multi-line paste is sent. Zero sends it
   * all at once. Console ports and old IOS boxes drop characters when a
   * forty-line config arrives in one burst; SecureCRT calls this "line send
   * delay", and people who need it need it badly.
   */
  lineDelayMs: number

  bell: BellMode
  /**
   * Redial a session whose connection dropped, after a short countdown.
   * Never on a clean logout, a refusal or a changed host key.
   */
  autoReconnect: boolean
  /** Ask before closing a tab whose session is still connected. */
  confirmClose: boolean

  layout: Layout
  /** The connection tree on the left, which a busy rack wants out of the way. */
  tree: boolean
  /** The command window under the terminals. */
  commandWindow: boolean
}

export const DEFAULT_PREFS: Prefs = {
  // Black on white, SecureCRT's own default, inside a light window.
  theme: 'traditional',
  fontSize: 14,
  fontFamily: 'default',
  scrollback: 10_000,
  cursorStyle: 'block',
  cursorBlink: true,
  copyOnSelect: true,
  rightClickPaste: true,
  pasteGuard: true,
  lineDelayMs: 0,
  bell: 'visual',
  autoReconnect: false,
  confirmClose: false,
  layout: 'single',
  tree: true,
  commandWindow: false,
}

const PREFS_KEY = 'bkd.terminal.prefs'
const PREFS_VERSION = 2

const pick = <T extends string>(value: unknown, allowed: readonly T[], fallback: T): T =>
  allowed.includes(value as T) ? (value as T) : fallback

const bool = (value: unknown, fallback: boolean): boolean =>
  value === undefined ? fallback : Boolean(value)

const clamp = (value: unknown, min: number, max: number, fallback: number): number => {
  const n = Number(value)
  return value !== undefined && Number.isFinite(n) && n >= min && n <= max ? n : fallback
}

export function loadPrefs(): Prefs {
  let parsed: Partial<Prefs> & { split?: boolean; v?: number } = {}
  try {
    parsed = JSON.parse(window.localStorage.getItem(PREFS_KEY) ?? '{}') ?? {}
  } catch {
    return DEFAULT_PREFS
  }
  const d = DEFAULT_PREFS
  return {
    // Before version 2 every browser stored the dark default whether or not
    // anyone chose it, so an old stored scheme is not a choice to keep.
    theme: parsed.v === PREFS_VERSION && parsed.theme && isThemeName(parsed.theme) ? parsed.theme : d.theme,
    fontSize: clamp(parsed.fontSize, 8, 32, d.fontSize),
    fontFamily: parsed.fontFamily && parsed.fontFamily in FONT_FAMILIES ? parsed.fontFamily : d.fontFamily,
    scrollback: clamp(parsed.scrollback, 500, 200_000, d.scrollback),
    cursorStyle: pick(parsed.cursorStyle, ['block', 'bar', 'underline'] as const, d.cursorStyle),
    cursorBlink: bool(parsed.cursorBlink, d.cursorBlink),
    copyOnSelect: bool(parsed.copyOnSelect, d.copyOnSelect),
    rightClickPaste: bool(parsed.rightClickPaste, d.rightClickPaste),
    pasteGuard: bool(parsed.pasteGuard, d.pasteGuard),
    lineDelayMs: clamp(parsed.lineDelayMs, 0, 5_000, d.lineDelayMs),
    bell: pick(parsed.bell, ['visual', 'sound', 'none'] as const, d.bell),
    autoReconnect: bool(parsed.autoReconnect, d.autoReconnect),
    confirmClose: bool(parsed.confirmClose, d.confirmClose),
    // The old boolean "split" becomes the two-pane layout rather than being
    // forgotten on upgrade.
    layout: pick(parsed.layout, ['single', 'split', 'grid'] as const,
      parsed.split ? 'split' : d.layout),
    tree: bool(parsed.tree, d.tree),
    commandWindow: bool(parsed.commandWindow, d.commandWindow),
  }
}

export function savePrefs(prefs: Prefs): void {
  try {
    window.localStorage.setItem(PREFS_KEY, JSON.stringify({ ...prefs, v: PREFS_VERSION }))
  } catch {
    // Private browsing, or a storage quota. Preferences are a convenience.
  }
}
