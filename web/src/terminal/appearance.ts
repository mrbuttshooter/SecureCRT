import type { Tree } from '../api'
import { isThemeName, type ThemeName } from './themes'

/** What a saved connection says about how its terminal should look. */
export interface Appearance {
  theme?: ThemeName
  fontSize?: number
}

/**
 * appearanceFor resolves a connection's colour scheme and font size the way
 * the server resolves everything else: the connection's own setting, then
 * its folder's default, then that folder's parent's, outward to the root.
 * Whatever is still unset falls through to this browser's preferences.
 *
 * Resolved here rather than asked of the server because the tree is already
 * in the browser, and a request per tab for two fields would be a poor
 * trade. The rule is the same one, nearest wins.
 */
export function appearanceFor(tree: Tree, sessionId: string | undefined): Appearance {
  if (!sessionId) return {}
  const session = tree.sessions.find((s) => s.id === sessionId)
  if (!session) return {}

  let scheme = session.settings?.colour_scheme ?? undefined
  let size = session.settings?.font_size ?? undefined

  const folders = new Map(tree.folders.map((f) => [f.id, f]))
  const seen = new Set<string>()
  let folder = folders.get(session.folder_id)
  while (folder && !seen.has(folder.id) && (scheme == null || size == null)) {
    seen.add(folder.id)
    scheme ??= folder.defaults?.colour_scheme ?? undefined
    size ??= folder.defaults?.font_size ?? undefined
    folder = folder.parent_id ? folders.get(folder.parent_id) : undefined
  }

  return {
    theme: scheme && isThemeName(scheme) ? scheme : undefined,
    fontSize: size && size >= 8 && size <= 32 ? size : undefined,
  }
}
