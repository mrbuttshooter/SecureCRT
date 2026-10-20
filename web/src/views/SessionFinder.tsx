import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { WindowDialog } from '../Chrome'
import type { SavedSession, Tree } from '../api'
import { SHORTCUTS } from '../terminal/keys'

/** An open tab, as much of it as the finder needs. */
export interface FinderTab {
  key: string
  label: string
  ended?: string
}

type Hit =
  | { kind: 'tab'; tab: FinderTab }
  | { kind: 'session'; session: SavedSession; path: string }

/**
 * SessionFinder is "type part of a hostname, press Enter" — SecureCRT's
 * Connect dialog with its filter box, reached from anywhere with one chord,
 * and finding open tabs as well as saved connections, because with twenty
 * tabs open the one you want is often already there.
 *
 * Matching is every word somewhere in name, host, user or folder path, so
 * "core lon" finds london-core-01 in Datacentres/London. Ranked by where the
 * first word matched, then by how recently the connection was used.
 */
export function SessionFinder({ tree, tabs, onConnect, onFocusTab, onClose }: {
  tree: Tree
  tabs: FinderTab[]
  onConnect: (session: SavedSession) => void
  onFocusTab: (key: string) => void
  onClose: () => void
}) {
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const list = useRef<HTMLUListElement>(null)
  const listId = useId()

  const paths = useMemo(() => {
    const folders = new Map(tree.folders.map((f) => [f.id, f]))
    const pathOf = (id: string): string => {
      const parts: string[] = []
      const seen = new Set<string>()
      let folder = folders.get(id)
      while (folder && !seen.has(folder.id)) {
        seen.add(folder.id)
        parts.unshift(folder.name)
        folder = folder.parent_id ? folders.get(folder.parent_id) : undefined
      }
      return parts.join(' / ')
    }
    return new Map(tree.sessions.map((s) => [s.id, pathOf(s.folder_id)]))
  }, [tree])

  const hits = useMemo<Hit[]>(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean)
    const matches = (haystack: string) => words.every((w) => haystack.includes(w))

    const openTabs: Hit[] = tabs
      .filter((t) => matches(t.label.toLowerCase()))
      .map((tab) => ({ kind: 'tab', tab }))

    const recency = (s: SavedSession) => (s.last_used_at ? Date.parse(s.last_used_at) : 0)
    const sessions = tree.sessions
      .map((session) => {
        const path = paths.get(session.id) ?? ''
        const hay = `${session.name} ${session.hostname} ${session.username} ${path}`.toLowerCase()
        if (!matches(hay)) return null
        const first = words[0] ?? ''
        const name = session.name.toLowerCase()
        const rank = !first ? 3
          : name.startsWith(first) ? 0
          : session.hostname.toLowerCase().startsWith(first) ? 1
          : name.includes(first) ? 2 : 3
        return { session, path, rank }
      })
      .filter((x): x is { session: SavedSession; path: string; rank: number } => x !== null)
      .sort((a, b) => a.rank - b.rank || recency(b.session) - recency(a.session)
        || a.session.name.localeCompare(b.session.name))
      .slice(0, query ? 50 : 12)
      .map(({ session, path }) => ({ kind: 'session' as const, session, path }))

    return [...openTabs, ...sessions]
  }, [query, tabs, tree, paths])

  useEffect(() => { setCursor(0) }, [query])

  useEffect(() => {
    list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [cursor])

  const choose = (hit: Hit | undefined) => {
    if (!hit) return
    onClose()
    if (hit.kind === 'tab') onFocusTab(hit.tab.key)
    else onConnect(hit.session)
  }

  return (
    <WindowDialog title="Connect" onClose={onClose} className="finder">
        <input
          autoFocus
          className="finder-input"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={hits[cursor] ? `${listId}-${cursor}` : undefined}
          aria-label="Type a name, host, user or folder"
          placeholder="Type a name, host, user or folder…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setCursor((c) => Math.min(hits.length - 1, c + 1)) }
            if (e.key === 'ArrowUp') { e.preventDefault(); setCursor((c) => Math.max(0, c - 1)) }
            if (e.key === 'Enter') { e.preventDefault(); choose(hits[cursor]) }
          }}
        />
        <ul className="finder-list" role="listbox" id={listId} ref={list} aria-label="Matches">
          {hits.length === 0 && (
            <li className="finder-empty muted">Nothing matches. Quick connect (Ctrl+Shift+Q) dials an address directly.</li>
          )}
          {hits.map((hit, i) => (
            <li
              key={hit.kind === 'tab' ? 't' + hit.tab.key : 's' + hit.session.id}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === cursor}
              className={'finder-item' + (i === cursor ? ' current' : '')}
              onMouseEnter={() => setCursor(i)}
              onMouseDown={(e) => { e.preventDefault(); choose(hit) }}
            >
              {hit.kind === 'tab' ? (
                <>
                  <span className="finder-kind">tab</span>
                  <span className="finder-name">{hit.tab.label}</span>
                  <span className="finder-meta muted">{hit.tab.ended ? 'ended' : 'open'}</span>
                </>
              ) : (
                <>
                  <span className="finder-kind">{hit.session.protocol}</span>
                  <span className="finder-name">{hit.session.name}</span>
                  <span className="finder-meta muted">
                    <span className="mono">
                      {hit.session.username ? hit.session.username + '@' : ''}{hit.session.hostname}
                    </span>
                    {hit.path && <> · {hit.path}</>}
                  </span>
                </>
              )}
            </li>
          ))}
        </ul>
        <p className="sr-only" role="status">{hits.length === 1 ? '1 match' : `${hits.length} matches`}</p>
        <p className="finder-hint muted">
          {'↑↓'} to choose · Enter to {hits[cursor]?.kind === 'tab' ? 'switch' : 'connect'} · Esc to close
        </p>
    </WindowDialog>
  )
}

/** ShortcutSheet is the keyboard map on screen, from the same list keys.ts binds. */
export function ShortcutSheet({ onClose }: { onClose: () => void }) {
  return (
    <WindowDialog title="Keyboard shortcuts" onClose={onClose} className="shortcuts">
        <dl className="shortcut-list">
          {SHORTCUTS.map(([keys, what]) => (
            <div key={keys + what} className="shortcut-row">
              <dt><kbd>{keys}</kbd></dt>
              <dd>{what}</dd>
            </div>
          ))}
        </dl>
        <p className="muted">
          Ctrl+T, Ctrl+W and Ctrl+Tab belong to the browser and never reach a
          web page, which is why tabs here use Alt and Ctrl+Shift instead.
        </p>
        <div className="dialog-footer">
          <button className="primary" onClick={onClose}>OK</button>
        </div>
    </WindowDialog>
  )
}
