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
  // SecureCRT's own default, black on white, for people who never changed it
  // and whose eyes now expect it.
  traditional: {
    background: '#ffffff', foreground: '#000000', cursor: '#000000',
    selectionBackground: '#a6c8ff',
    black: '#000000', red: '#c00000', green: '#008000', yellow: '#808000',
    blue: '#0000c0', magenta: '#c000c0', cyan: '#008080', white: '#c0c0c0',
    brightBlack: '#808080', brightRed: '#ff0000', brightGreen: '#00a000',
    brightYellow: '#a0a000', brightBlue: '#0000ff', brightMagenta: '#ff00ff',
    brightCyan: '#00a0a0', brightWhite: '#606060',
  },
  // The oldest trick in a network team's book: production gets a background
  // nobody can mistake for the lab. Dark enough to read on for hours, red
  // enough that the hand hesitates before "reload".
  production: {
    background: '#2a0d0f', foreground: '#f2d7d5', cursor: '#ff6b6b',
    selectionBackground: '#6b2a2e',
    black: '#4a2326', red: '#ff7b72', green: '#7ee787', yellow: '#f2cc60',
    blue: '#79c0ff', magenta: '#d2a8ff', cyan: '#76e3ea', white: '#e6d3d1',
    brightBlack: '#8a5a5d', brightRed: '#ffa198', brightGreen: '#a5f0ae',
    brightYellow: '#f8dd8a', brightBlue: '#a5d6ff', brightMagenta: '#e2c5ff',
    brightCyan: '#b3f0f5', brightWhite: '#fff5f4',
  },
  // A calm amber for staging, the same idea one step down.
  staging: {
    background: '#211a08', foreground: '#ecdfc0', cursor: '#f2b632',
    selectionBackground: '#5a4719',
    black: '#3f3418', red: '#ff7b72', green: '#8fd18a', yellow: '#f2b632',
    blue: '#7fb6ff', magenta: '#d6a6ff', cyan: '#6fd6d6', white: '#ddd2b6',
    brightBlack: '#7a6a43', brightRed: '#ffa198', brightGreen: '#b0e8a9',
    brightYellow: '#ffd36a', brightBlue: '#a9cfff', brightMagenta: '#e6c6ff',
    brightCyan: '#a4ecec', brightWhite: '#fff8e6',
  },
  solarized_light: {
    background: '#fdf6e3', foreground: '#586e75', cursor: '#586e75',
    selectionBackground: '#eee8d5',
    black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900',
    blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#93a1a1',
    brightBlack: '#002b36', brightRed: '#cb4b16', brightGreen: '#586e75',
    brightYellow: '#657b83', brightBlue: '#839496', brightMagenta: '#6c71c4',
    brightCyan: '#586e75', brightWhite: '#073642',
  },
  dracula: {
    background: '#282a36', foreground: '#f8f8f2', cursor: '#f8f8f2',
    selectionBackground: '#44475a',
    black: '#21222c', red: '#ff5555', green: '#50fa7b', yellow: '#f1fa8c',
    blue: '#bd93f9', magenta: '#ff79c6', cyan: '#8be9fd', white: '#f8f8f2',
    brightBlack: '#6272a4', brightRed: '#ff6e6e', brightGreen: '#69ff94',
    brightYellow: '#ffffa5', brightBlue: '#d6acff', brightMagenta: '#ff92df',
    brightCyan: '#a4ffff', brightWhite: '#ffffff',
  },
  nord: {
    background: '#2e3440', foreground: '#d8dee9', cursor: '#d8dee9',
    selectionBackground: '#434c5e',
    black: '#3b4252', red: '#bf616a', green: '#a3be8c', yellow: '#ebcb8b',
    blue: '#81a1c1', magenta: '#b48ead', cyan: '#88c0d0', white: '#e5e9f0',
    brightBlack: '#4c566a', brightRed: '#bf616a', brightGreen: '#a3be8c',
    brightYellow: '#ebcb8b', brightBlue: '#81a1c1', brightMagenta: '#b48ead',
    brightCyan: '#8fbcbb', brightWhite: '#eceff4',
  },
  monokai: {
    background: '#272822', foreground: '#f8f8f2', cursor: '#f8f8f0',
    selectionBackground: '#49483e',
    black: '#272822', red: '#f92672', green: '#a6e22e', yellow: '#f4bf75',
    blue: '#66d9ef', magenta: '#ae81ff', cyan: '#a1efe4', white: '#f8f8f2',
    brightBlack: '#75715e', brightRed: '#f92672', brightGreen: '#a6e22e',
    brightYellow: '#f4bf75', brightBlue: '#66d9ef', brightMagenta: '#ae81ff',
    brightCyan: '#a1efe4', brightWhite: '#f9f8f5',
  },
}

export type ThemeName = keyof typeof THEMES

export const THEME_LABELS: Record<string, string> = {
  dark: 'Dark',
  light: 'Light',
  traditional: 'Traditional (black on white)',
  production: 'Production (red)',
  staging: 'Staging (amber)',
  solarized_dark: 'Solarized dark',
  solarized_light: 'Solarized light',
  green_screen: 'Green screen',
  dracula: 'Dracula',
  nord: 'Nord',
  monokai: 'Monokai',
}

/** The sizes offered wherever a font size is chosen. */
export const FONT_SIZES = [10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24] as const

/** Monospace faces worth offering; the first one installed wins. */
export const FONT_FAMILIES: Record<string, string> = {
  // Consolas first: SecureCRT's own default on Windows.
  default: 'Consolas, "Cascadia Mono", "DejaVu Sans Mono", Menlo, monospace',
  cascadia: '"Cascadia Mono", "Cascadia Code", Consolas, monospace',
  lucida: '"Lucida Console", Consolas, monospace',
  courier: '"Courier New", Courier, monospace',
  menlo: 'Menlo, Monaco, monospace',
}

export const FONT_FAMILY_LABELS: Record<string, string> = {
  default: 'Consolas',
  cascadia: 'Cascadia Mono',
  lucida: 'Lucida Console',
  courier: 'Courier New',
  menlo: 'Menlo (Mac)',
}

export function isThemeName(value: string): value is ThemeName {
  return value in THEMES
}
