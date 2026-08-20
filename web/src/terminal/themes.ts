import type { ITheme } from '@xterm/xterm'

/**
 * Colour schemes.
 *
 * Network equipment leans hard on ANSI colour — Cisco syntax highlighting,
 * `show` output, journalctl priorities — so these are chosen for legibility
 * of the 16 ANSI colours against the background rather than for looks. Each
 * keeps the standard colours distinguishable at small sizes, which the more
 * fashionable low-contrast schemes do not.
 */
export const THEMES: Record<string, ITheme> = {
  dark: {
    background: '#11151c', foreground: '#c9d1d9', cursor: '#58a6ff',
    selectionBackground: '#2d4f76',
    black: '#484f58', red: '#ff7b72', green: '#3fb950', yellow: '#d29922',
    blue: '#58a6ff', magenta: '#bc8cff', cyan: '#39c5cf', white: '#b1bac4',
    brightBlack: '#6e7681', brightRed: '#ffa198', brightGreen: '#56d364',
    brightYellow: '#e3b341', brightBlue: '#79c0ff', brightMagenta: '#d2a8ff',
    brightCyan: '#56d4dd', brightWhite: '#f0f6fc',
  },
  light: {
    background: '#ffffff', foreground: '#24292f', cursor: '#0969da',
    selectionBackground: '#b6d8fd',
    black: '#24292f', red: '#cf222e', green: '#116329', yellow: '#7d4e00',
    blue: '#0969da', magenta: '#8250df', cyan: '#1b7c83', white: '#6e7781',
    brightBlack: '#57606a', brightRed: '#a40e26', brightGreen: '#1a7f37',
    brightYellow: '#633c01', brightBlue: '#218bff', brightMagenta: '#a475f9',
    brightCyan: '#3192aa', brightWhite: '#8c959f',
  },
  solarized_dark: {
    background: '#002b36', foreground: '#93a1a1', cursor: '#93a1a1',
    selectionBackground: '#073642',
    black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900',
    blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#eee8d5',
    brightBlack: '#586e75', brightRed: '#cb4b16', brightGreen: '#586e75',
    brightYellow: '#657b83', brightBlue: '#839496', brightMagenta: '#6c71c4',
    brightCyan: '#93a1a1', brightWhite: '#fdf6e3',
  },
  // Included because it is what a great many engineers have used on a serial
  // console for twenty years, and familiarity counts for something.
  green_screen: {
    background: '#001100', foreground: '#33ff33', cursor: '#33ff33',
    selectionBackground: '#0a3d0a',
    black: '#003300', red: '#00cc00', green: '#33ff33', yellow: '#66ff66',
    blue: '#00aa00', magenta: '#00dd00', cyan: '#55ff55', white: '#ccffcc',
    brightBlack: '#005500', brightRed: '#33ff33', brightGreen: '#66ff66',
    brightYellow: '#99ff99', brightBlue: '#33cc33', brightMagenta: '#44ee44',
    brightCyan: '#88ff88', brightWhite: '#eeffee',
  },
}

export type ThemeName = keyof typeof THEMES

export const THEME_LABELS: Record<string, string> = {
  dark: 'Dark',
  light: 'Light',
  solarized_dark: 'Solarized dark',
  green_screen: 'Green screen',
}

export function isThemeName(value: string): value is ThemeName {
  return value in THEMES
}
