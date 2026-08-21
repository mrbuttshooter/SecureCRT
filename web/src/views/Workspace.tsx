import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError, api,
  type Folder, type LiveTerminal, type SavedSession, type Tree,
} from '../api'
import { SessionTree } from './SessionTree'
import { SessionEditor } from './SessionEditor'
import { FolderEditor } from './FolderEditor'
import { ConsoleServer } from './ConsoleServer'
import { TerminalPane } from '../terminal/TerminalPane'
import { SnippetBar } from '../terminal/SessionTools'
import { QuickConnect } from './QuickConnect'
import { ContextMenu, type MenuItem } from '../ContextMenu'
import { commandFor } from '../terminal/keys'
import { THEME_LABELS, isThemeName, type ThemeName } from '../terminal/themes'

/** A tab is one terminal, live or being opened. */
interface Tab {
  /** Stable client-side key. The server-side terminal ID arrives later. */
  key: string
  label: string
  sessionId?: string
  terminalId?: string
  ended?: string
  /** One of six marker colours, or undefined for none. */
  colour?: number
}

type Panel =
  | { kind: 'none' }
  | { kind: 'session'; session: SavedSession | null; folderId: string }
  | { kind: 'folder'; folder: Folder | null; parentId: string }
  | { kind: 'console'; folderId: string }

const PREFS_KEY = 'bkd.terminal.prefs'

interface Prefs {
  theme: ThemeName
  fontSize: number
  scrollback: number
  /** Panes shown side by side, rather than one at a time. */
  split: boolean
  /** The connection tree on the left, which a busy rack wants out of the way. */
  tree: boolean
  /** Ask before pasting more than one line into a terminal. */
  pasteGuard: boolean
}

const DEFAULT_PREFS: Prefs = {
  theme: 'dark', fontSize: 14, scrollback: 10_000, split: false, tree: true,
  pasteGuard: true,
}

/** Where the open tabs are remembered, so a reload can offer them back. */
const TABS_KEY = 'bkd.terminal.tabs'

/**
 * Workspace is where the work happens: the saved connection tree on the left,
 * terminal tabs on the right.
 *
 * Tabs are never unmounted while they are open, only hidden. Unmounting would
 * dispose the xterm instance and throw away the scrollback the user can see —
 * the server would still hold the session, but the visible history would be
 * gone, which is not what "switch tab and back" should mean.
 */
export function Workspace({ active }: { active: boolean }) {
  const [tree, setTree] = useState<Tree>({ folders: [], sessions: [] })
  const [live, setLive] = useState<LiveTerminal[]>([])
  const [tabs, setTabs] = useState<Tab[]>([])
  const [activeKey, setActiveKey] = useState<string | null>(null)
  const [selected, setSelected] = useState<SavedSession | null>(null)
  const [panel, setPanel] = useState<Panel>({ kind: 'none' })
  const [filter, setFilter] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs)
  const [tabMenu, setTabMenu] = useState<{ x: number; y: number; key: string } | null>(null)
  // Ctrl+click multi-selection in the tree, for bulk connect and delete.
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const dragTab = useRef<string | null>(null)
  const [quickFocus, setQuickFocus] = useState(0)
  // Most-recently-active tab keys, newest first. Split mode shows the top
  // two, so what is on screen always includes the tab you last clicked —
  // showing anything else while focus follows activeKey was a
  // keystrokes-into-a-hidden-pane bug.
  const [recency, setRecency] = useState<string[]>([])
  const nextKey = useRef(0)
  const restored = useRef(false)
  const filterInput = useRef<HTMLInputElement>(null)

  const focusTab = useCallback((key: string) => {
    setActiveKey(key)
    setRecency((prev) => [key, ...prev.filter((k) => k !== key)])
  }, [])

  useEffect(() => {
    try {
      window.localStorage.setItem(PREFS_KEY, JSON.stringify(prefs))
    } catch {
      // Private browsing, or a storage quota. Preferences are a convenience.
    }
  }, [prefs])

  // The open tabs are remembered so a reload does not scatter the workspace.
  useEffect(() => {
    if (!restored.current) return
    try {
      window.localStorage.setItem(TABS_KEY, JSON.stringify({
        tabs: tabs.map((t) => ({
          label: t.label, sessionId: t.sessionId,
          terminalId: t.terminalId, colour: t.colour,
        })),
        active: tabs.findIndex((t) => t.key === activeKey),
      }))
    } catch { /* convenience only */ }
  }, [tabs, activeKey])


  const loadTree = useCallback(async () => {
    try {
      setTree(await api.get<Tree>('/api/tree'))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [])

  const loadLive = useCallback(async () => {
    try {
      const r = await api.get<{ terminals: LiveTerminal[] }>('/api/terminals')
      setLive(r.terminals ?? [])
    } catch {
      // A transient failure here only means the "still running" markers are
      // briefly stale, which is not worth an error banner.
    }
  }, [])

  // On mount: reattach every remembered tab whose terminal is still running.
  // Only the living come back — auto-redialling dead sessions on reload
  // would be this browser deciding to dial switches on its own.
  useEffect(() => {
    if (restored.current) return
    restored.current = true
    void (async () => {
      let saved: { tabs?: Array<Partial<Tab>>; active?: number }
      try {
        saved = JSON.parse(window.localStorage.getItem(TABS_KEY) ?? '{}')
      } catch { return }
      if (!saved.tabs?.length) return
      let alive: Set<string>
      try {
        const r = await api.get<{ terminals: LiveTerminal[] }>('/api/terminals')
        alive = new Set((r.terminals ?? []).filter((t) => !t.closed).map((t) => t.id))
      } catch { return }
      const revived = saved.tabs
        .filter((t) => t.terminalId && alive.has(t.terminalId))
        .map((t) => ({
          key: `tab-${nextKey.current++}`,
          label: t.label ?? 'terminal',
          sessionId: t.sessionId,
          terminalId: t.terminalId,
          colour: t.colour,
        }))
      if (!revived.length) return
      setTabs(revived)
      const wanted = saved.tabs[saved.active ?? -1]?.terminalId
      const focus = revived.find((t) => t.terminalId === wanted) ?? revived.at(-1)!
      setActiveKey(focus.key)
      setRecency(revived.map((t) => t.key).reverse())
      void loadLive()
    })()
  }, [loadLive])


  // Reloaded whenever this becomes the visible tab, not only on mount. The
  // workspace stays mounted while another tab is in front — that is what
  // keeps terminals alive — so without this an import of two hundred devices
  // performed on the transfer tab would leave the connection tree looking
  // exactly as empty as before, and the obvious conclusion would be that the
  // import had failed. One GET on each switch is a cheap way not to lie.
  useEffect(() => {
    if (!active) return
    void loadTree()
    void loadLive()
  }, [active, loadTree, loadLive])

  const liveSessionIds = useMemo(
    () => new Set(live.filter((t) => !t.closed && t.session_id).map((t) => t.session_id!)),
    [live],
  )

  // Terminals still running from a previous browser, not shown in any tab
  // here. Surfacing them is the visible payoff of server-side survival.
  const orphans = useMemo(
    () => live.filter((t) => !t.closed && !tabs.some((tab) => tab.terminalId === t.id)),
    [live, tabs],
  )

  const openTab = (tab: Omit<Tab, 'key'>) => {
    const key = `tab-${nextKey.current++}`
    setTabs((prev) => [...prev, { ...tab, key }])
    focusTab(key)
  }

  const connect = (session: SavedSession) => {
    // A saved connection can be opened more than once — two windows onto the
    // same switch is normal — so this always opens a tab rather than
    // focusing an existing one.
    openTab({ label: session.name, sessionId: session.id })
    void loadLive()
  }

  const reattach = (t: LiveTerminal) => {
    // The saved-connection id comes along so that when this terminal
    // eventually ends, the tab can still redial. Dropping it made orphan
    // tabs unreconnectable corpses.
    openTab({ label: t.label || t.host, terminalId: t.id, sessionId: t.session_id })
  }

  const closeTab = async (key: string) => {
    const tab = tabs.find((t) => t.key === key)
    setTabs((prev) => prev.filter((t) => t.key !== key))
    setRecency((prev) => prev.filter((k) => k !== key))
    setActiveKey((current) => {
      if (current !== key) return current
      // The neighbour, not the far end of the strip: closing tab 3 of 8
      // should land you on 4, the way every tabbed application works.
      const index = tabs.findIndex((t) => t.key === key)
      const remaining = tabs.filter((t) => t.key !== key)
      return (remaining[index] ?? remaining[index - 1])?.key ?? null
    })

    // Closing a tab ends the session. Leaving it running would be worse: an
    // invisible SSH session holding a device's vty line is exactly what
    // people complain about with web terminals.
    if (tab?.terminalId) {
      try {
        await api.delete(`/api/terminals/${tab.terminalId}`)
      } catch {
        // Already gone, most likely.
      }
    }
    void loadLive()
  }

  const move = async (kind: 'folder' | 'session', id: string, destination: string) => {
    const path = kind === 'folder' ? `/api/tree/folders/${id}` : `/api/tree/sessions/${id}`
    const body = kind === 'folder' ? { parent_id: destination } : { folder_id: destination }
    try {
      await api.patch(path, body)
      await loadTree()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    }
  }

  const deleteFolder = async (folder: Folder) => {
    try {
      await api.delete(`/api/tree/folders/${folder.id}`)
      await loadTree()
      return
    } catch (err) {
      if (!(err instanceof ApiError) || err.code !== 'folder_not_empty') {
        setError(err instanceof Error ? err.message : String(err))
        return
      }
      // The server reports exactly what is at stake, so the confirmation can
      // name it rather than asking a vague "are you sure?".
      const folders = Number(err.details.folders ?? 0)
      const sessions = Number(err.details.sessions ?? 0)
      const parts = [
        sessions === 1 ? '1 connection' : `${sessions} connections`,
        folders === 1 ? '1 folder' : `${folders} folders`,
      ]
      if (!window.confirm(
        `“${folder.name}” contains ${parts.join(' and ')}. Delete all of it? This cannot be undone.`,
      )) return
    }

    try {
      await api.delete(`/api/tree/folders/${folder.id}?recursive=true`)
      await loadTree()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const deleteSession = async (session: SavedSession) => {
    if (!window.confirm(`Delete the saved connection “${session.name}”?`)) return
    try {
      await api.delete(`/api/tree/sessions/${session.id}`)
      if (selected?.id === session.id) setSelected(null)
      await loadTree()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  // Split shows the active tab plus the one used most recently before it.
  const shown = prefs.split
    ? tabs.filter((t) => recency.slice(0, 2).includes(t.key))
    : tabs.filter((t) => t.key === activeKey)

  const activeTab = tabs.find((t) => t.key === activeKey) ?? null

  // The chords the panes claim from xterm bubble up to here; this listener
  // is also what makes them work when focus is in the tree or the filter.
  useEffect(() => {
    if (!active) return
    const onKey = (event: KeyboardEvent) => {
      const command = commandFor(event)
      if (!command) return
      switch (command.kind) {
        case 'jump': {
          const target = tabs[command.index]
          if (target) { event.preventDefault(); focusTab(target.key) }
          break
        }
        case 'next-tab':
        case 'prev-tab': {
          if (tabs.length < 2) break
          event.preventDefault()
          const at = Math.max(0, tabs.findIndex((t) => t.key === activeKey))
          const step = command.kind === 'next-tab' ? 1 : tabs.length - 1
          focusTab(tabs[(at + step) % tabs.length]!.key)
          break
        }
        case 'quick-connect':
          event.preventDefault()
          setQuickFocus((n) => n + 1)
          if (!prefs.tree) setPrefs((p) => ({ ...p, tree: true }))
          break
        case 'filter':
          event.preventDefault()
          if (!prefs.tree) setPrefs((p) => ({ ...p, tree: true }))
          window.setTimeout(() => filterInput.current?.focus(), 0)
          break
        case 'close-tab':
          if (activeKey) { event.preventDefault(); void closeTab(activeKey) }
          break
        case 'duplicate-tab': {
          const current = tabs.find((t) => t.key === activeKey)
          if (current?.sessionId) {
            event.preventDefault()
            openTab({ label: current.label, sessionId: current.sessionId })
          }
          break
        }
        // find and broadcast are handled inside the focused pane.
        case 'find':
        case 'broadcast':
          break
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  })

  // Everything a right-click on a tab offers. Reconnect lives on the pane
  // itself, where the Ended state is; this menu is about tab housekeeping.
  const tabMenuItems = (key: string): MenuItem[] => {
    const tab = tabs.find((t) => t.key === key)
    if (!tab) return []
    const at = tabs.findIndex((t) => t.key === key)
    return [
      {
        label: 'Duplicate',
        disabled: !tab.sessionId,
        onClick: () => openTab({ label: tab.label, sessionId: tab.sessionId }),
      },
      {
        label: 'Rename…',
        onClick: () => {
          const name = window.prompt('Tab name', tab.label)
          if (name?.trim()) {
            setTabs((prev) => prev.map((t) => (t.key === key ? { ...t, label: name.trim() } : t)))
          }
        },
      },
      {
        label: tab.colour === undefined ? 'Mark with a colour' : 'Next colour',
        onClick: () => setTabs((prev) => prev.map((t) =>
          t.key === key ? { ...t, colour: ((t.colour ?? -1) + 1) % 6 } : t)),
      },
      ...(tab.colour !== undefined
        ? [{
            label: 'Clear the colour',
            onClick: () => setTabs((prev) => prev.map((t) =>
              t.key === key ? { ...t, colour: undefined } : t)),
          }]
        : []),
      { label: '—', disabled: true, onClick: () => {} },
      { label: 'Close', danger: true, onClick: () => void closeTab(key) },
      {
        label: 'Close the others',
        danger: true,
        disabled: tabs.length < 2,
        onClick: () => tabs.filter((t) => t.key !== key).forEach((t) => void closeTab(t.key)),
      },
      {
        label: 'Close to the right',
        danger: true,
        disabled: at === tabs.length - 1,
        onClick: () => tabs.slice(at + 1).forEach((t) => void closeTab(t.key)),
      },
    ]
  }

  return (
    <div className={'workspace' + (prefs.tree ? '' : ' collapsed')}>
      <aside className="sidebar" hidden={!prefs.tree}>
        <div className="sidebar-head">
          <QuickConnect
            tree={tree}
            focusSignal={quickFocus}
            onConnected={(session) => connect(session)}
            onTreeChanged={() => void loadTree()}
          />
          <input
            ref={filterInput}
            className="filter"
            aria-label="Filter connections"
            placeholder="Filter by name, host or user"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <div className="row">
            <button onClick={() => setPanel({ kind: 'session', session: null, folderId: '' })}>
              New connection
            </button>
            <button onClick={() => setPanel({ kind: 'folder', folder: null, parentId: '' })}>
              New folder
            </button>
            <button onClick={() => setPanel({ kind: 'console', folderId: '' })}>
              Console server
            </button>
          </div>
        </div>

        {/*
          The open terminals, with their state, before the saved tree — the
          way SecureCRT's session manager keeps Active Sessions in reach.
          Click focuses the tab; the cross ends the session. With a dozen
          NewsLeb tabs open, this list is how you find the one that died.
        */}
        {tabs.length > 0 && (
          <div className="open-tabs">
            <h3>Open terminals</h3>
            <ul className="plain">
              {tabs.map((t) => (
                <li key={t.key}
                    className={'open-tab' + (t.key === activeKey ? ' current' : '')}>
                  <span className={'open-tab-dot ' + (t.ended ? 'dot-ended' : t.terminalId ? 'dot-live' : 'dot-opening')} />
                  <button className="open-tab-label" title={t.ended ?? undefined}
                          onClick={() => focusTab(t.key)}>
                    {t.label}
                  </button>
                  <button className="open-tab-close" aria-label={`Close ${t.label}`}
                          onClick={() => void closeTab(t.key)}>
                    {'×'}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <SessionTree
          tree={tree}
          liveSessionIds={liveSessionIds}
          selectedId={selected?.id ?? null}
          filter={filter}
          onOpen={connect}
          onSelect={setSelected}
          onEditFolder={(folder) => setPanel({ kind: 'folder', folder, parentId: folder.parent_id })}
          onDeleteFolder={(folder) => void deleteFolder(folder)}
          onNewSessionIn={(folderId) => setPanel({ kind: 'session', session: null, folderId })}
          onNewFolderIn={(parentId) => setPanel({ kind: 'folder', folder: null, parentId })}
          onEditSession={(session) => setPanel({ kind: 'session', session, folderId: session.folder_id })}
          onDeleteSession={(session) => void deleteSession(session)}
          checkedIds={checked}
          onToggleCheck={(session) => setChecked((prev) => {
            const next = new Set(prev)
            if (next.has(session.id)) next.delete(session.id)
            else next.add(session.id)
            return next
          })}
          onMove={(kind, id, destination) => void move(kind, id, destination)}
        />

        {orphans.length > 0 && (
          <div className="orphans">
            <h3>Still running</h3>
            <p className="muted">
              Sessions left open elsewhere. They kept running while you were away.
            </p>
            <ul className="plain">
              {orphans.map((t) => (
                <li key={t.id}>
                  <button className="link" onClick={() => reattach(t)}>
                    {t.label || t.host} <span className="muted">reattach</span>
                  </button>
                </li>
              ))}
            </ul>
            {orphans.length > 1 && (
              <button className="link"
                      onClick={() => orphans.forEach((t) => reattach(t))}>
                Reattach all {orphans.length}
              </button>
            )}
          </div>
        )}

        {checked.size > 1 && (
          <div className="selection">
            <h3>{checked.size} selected</h3>
            <p className="muted">Ctrl+click adds or removes a connection.</p>
            <div className="row">
              <button onClick={() => {
                const picked = tree.sessions.filter((s) => checked.has(s.id))
                if (picked.length <= 5 || window.confirm(
                  `Open ${picked.length} terminals, one per selected connection?`)) {
                  picked.forEach((s) => connect(s))
                }
              }}>
                Connect all {checked.size}
              </button>
              <button onClick={() => setChecked(new Set())}>Clear</button>
              <button className="danger" onClick={() => {
                const picked = tree.sessions.filter((s) => checked.has(s.id))
                if (!window.confirm(
                  `Delete ${picked.length} saved connections? This cannot be undone.`)) return
                void (async () => {
                  for (const s of picked) {
                    try {
                      await api.delete(`/api/tree/sessions/${s.id}`)
                    } catch { /* gone already */ }
                  }
                  setChecked(new Set())
                  await loadTree()
                })()
              }}>
                Delete {checked.size}
              </button>
            </div>
          </div>
        )}

        {checked.size <= 1 && selected && (
          <div className="selection">
            <h3>{selected.name}</h3>
            <p className="muted">
              {selected.username ? `${selected.username}@` : ''}
              {selected.protocol === 'serial'
                ? selected.hostname
                : `${selected.hostname}:${selected.effective_port}`}
              {' · '}{selected.protocol}
              {selected.protocol !== 'ssh' && (
                <> · <span className="tag warn-tag">not encrypted</span></>
              )}
            </p>
            <div className="row">
              <button onClick={() => connect(selected)}>Connect</button>
              <button onClick={() =>
                setPanel({ kind: 'session', session: selected, folderId: selected.folder_id })}>
                Edit
              </button>
              <button className="danger" onClick={() => void deleteSession(selected)}>Delete</button>
            </div>
          </div>
        )}
      </aside>

      <section className="terminals">
        <div className="tabstrip" role="tablist">
          <button
            className="link tree-toggle"
            aria-label={prefs.tree ? 'Hide the connection tree' : 'Show the connection tree'}
            title={prefs.tree ? 'Hide the connection tree' : 'Show the connection tree'}
            onClick={() => setPrefs((p) => ({ ...p, tree: !p.tree }))}
          >
            {prefs.tree ? '◂▌' : '▌▸'}
          </button>
          {tabs.map((tab) => (
            <div
              key={tab.key}
              role="tab"
              aria-selected={tab.key === activeKey}
              className={'tab' + (tab.key === activeKey ? ' active' : '')
                + (tab.colour !== undefined ? ` tab-c${tab.colour}` : '')}
              onContextMenu={(e) => {
                e.preventDefault()
                setTabMenu({ x: e.clientX, y: e.clientY, key: tab.key })
              }}
              draggable
              onDragStart={() => { dragTab.current = tab.key }}
              onDragOver={(e) => { if (dragTab.current) e.preventDefault() }}
              onDrop={(e) => {
                e.preventDefault()
                const from = dragTab.current
                dragTab.current = null
                if (!from || from === tab.key) return
                setTabs((prev) => {
                  const moving = prev.find((t) => t.key === from)
                  if (!moving) return prev
                  const without = prev.filter((t) => t.key !== from)
                  const at = without.findIndex((t) => t.key === tab.key)
                  return [...without.slice(0, at), moving, ...without.slice(at)]
                })
              }}
            >
              <span className={'open-tab-dot ' +
                (tab.ended ? 'dot-ended' : tab.terminalId ? 'dot-live' : 'dot-opening')} />
              <button className="tab-label" onClick={() => focusTab(tab.key)}>
                {tab.label}
                {tab.ended && <span className="muted"> · ended</span>}
              </button>
              <button className="tab-close" aria-label={`Close ${tab.label}`}
                      onClick={() => void closeTab(tab.key)}>×</button>
            </div>
          ))}

          <div className="tabstrip-tools">
            {tabs.filter((t) => t.ended && t.sessionId).length > 1 && (
              <button className="link"
                      title="Redial every ended tab, in place"
                      onClick={() => window.dispatchEvent(new CustomEvent('bkd:reconnect-all'))}>
                Reconnect all {tabs.filter((t) => t.ended && t.sessionId).length}
              </button>
            )}
            <label className="inline"
                   title="Ask before pasting more than one line into a terminal">
              <input
                type="checkbox"
                checked={prefs.pasteGuard}
                onChange={(e) => setPrefs((p) => ({ ...p, pasteGuard: e.target.checked }))}
              />
              Paste guard
            </label>
            <label className="inline">
              <input type="checkbox" checked={prefs.split}
                     onChange={(e) => setPrefs({ ...prefs, split: e.target.checked })} />
              Split
            </label>
            <select
              aria-label="Colour scheme"
              value={prefs.theme}
              onChange={(e) => {
                const value = e.target.value
                if (isThemeName(value)) setPrefs({ ...prefs, theme: value })
              }}
            >
              {Object.entries(THEME_LABELS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
            <select
              aria-label="Font size"
              value={String(prefs.fontSize)}
              onChange={(e) => setPrefs({ ...prefs, fontSize: Number(e.target.value) })}
            >
              {[11, 12, 13, 14, 16, 18, 20].map((n) => (
                <option key={n} value={n}>{n}px</option>
              ))}
            </select>
          </div>
        </div>

        {error && <div className="error">{error}</div>}

        {panel.kind === 'session' && (
          <SessionEditor
            session={panel.session}
            folderId={panel.folderId}
            onSaved={(saved, connectNow) => {
              setPanel({ kind: 'none' })
              void loadTree()
              // The saved connection is selected rather than dropped on the
              // floor, and "Create and connect" does what it says.
              setSelected(saved)
              if (connectNow) connect(saved)
            }}
            onCancel={() => setPanel({ kind: 'none' })}
          />
        )}

        {panel.kind === 'console' && (
          <ConsoleServer
            folderId={panel.folderId}
            onCreated={() => { setPanel({ kind: 'none' }); void loadTree() }}
            onCancel={() => setPanel({ kind: 'none' })}
          />
        )}

        {panel.kind === 'folder' && (
          <FolderEditor
            folder={panel.folder}
            parentId={panel.parentId}
            onSaved={() => { setPanel({ kind: 'none' }); void loadTree() }}
            onCancel={() => setPanel({ kind: 'none' })}
          />
        )}

        <div className={'panes' + (prefs.split && shown.length > 1 ? ' split' : '')}>
          {tabs.map((tab) => (
            <div
              key={tab.key}
              className="pane-slot"
              hidden={!shown.some((s) => s.key === tab.key)}
            >
              <TerminalPane
                paneKey={tab.key}
                sessionId={tab.sessionId}
                terminalId={tab.terminalId}
                label={tab.label}
                theme={prefs.theme}
                fontSize={prefs.fontSize}
                scrollback={prefs.scrollback}
                active={tab.key === activeKey}
                pasteGuard={prefs.pasteGuard}
                otherTerminals={live}
                onTerminalID={(id) => {
                  // A fresh terminal id also means a successful redial, so
                  // the record of the previous death is cleared with it.
                  setTabs((prev) =>
                    prev.map((t) =>
                      t.key === tab.key ? { ...t, terminalId: id, ended: undefined } : t))
                  void loadLive()
                }}
                onReconnected={() => {
                  setTabs((prev) =>
                    prev.map((t) => (t.key === tab.key ? { ...t, ended: undefined } : t)))
                }}
                onEnded={(reason) => {
                  setTabs((prev) =>
                    prev.map((t) => (t.key === tab.key ? { ...t, ended: reason } : t)))
                  void loadLive()
                }}
              />
            </div>
          ))}

          {tabs.length === 0 && panel.kind === 'none' && (
            <div className="empty-terminals">
              <h2>No terminal open</h2>
              <p className="muted">
                Pick a connection on the left and press Connect, or double-click it.
              </p>
            </div>
          )}
        </div>

        {tabs.length > 0 && (
          <SnippetBar terminalId={activeTab && !activeTab.ended ? activeTab.terminalId ?? null : null} />
        )}
      </section>

      {tabMenu && (
        <ContextMenu
          x={tabMenu.x}
          y={tabMenu.y}
          items={tabMenuItems(tabMenu.key)}
          onClose={() => setTabMenu(null)}
        />
      )}
    </div>
  )
}

function loadPrefs(): Prefs {
  try {
    const raw = window.localStorage.getItem(PREFS_KEY)
    if (!raw) return DEFAULT_PREFS
    const parsed = JSON.parse(raw) as Partial<Prefs>
    return {
      theme: parsed.theme && isThemeName(parsed.theme) ? parsed.theme : DEFAULT_PREFS.theme,
      fontSize: Number(parsed.fontSize) || DEFAULT_PREFS.fontSize,
      scrollback: Number(parsed.scrollback) || DEFAULT_PREFS.scrollback,
      split: Boolean(parsed.split),
      tree: parsed.tree === undefined ? true : Boolean(parsed.tree),
      pasteGuard: parsed.pasteGuard === undefined ? true : Boolean(parsed.pasteGuard),
    }
  } catch {
    return DEFAULT_PREFS
  }
}
