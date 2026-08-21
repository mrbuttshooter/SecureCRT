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
import { THEME_LABELS, isThemeName, type ThemeName } from '../terminal/themes'

/** A tab is one terminal, live or being opened. */
interface Tab {
  /** Stable client-side key. The server-side terminal ID arrives later. */
  key: string
  label: string
  sessionId?: string
  terminalId?: string
  ended?: string
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
}

const DEFAULT_PREFS: Prefs = {
  theme: 'dark', fontSize: 14, scrollback: 10_000, split: false, tree: true,
}

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
  const nextKey = useRef(0)

  useEffect(() => {
    try {
      window.localStorage.setItem(PREFS_KEY, JSON.stringify(prefs))
    } catch {
      // Private browsing, or a storage quota. Preferences are a convenience.
    }
  }, [prefs])

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
    setActiveKey(key)
  }

  const connect = (session: SavedSession) => {
    // A saved connection can be opened more than once — two windows onto the
    // same switch is normal — so this always opens a tab rather than
    // focusing an existing one.
    openTab({ label: session.name, sessionId: session.id })
    void loadLive()
  }

  const reattach = (t: LiveTerminal) => {
    openTab({ label: t.label || t.host, terminalId: t.id })
  }

  const closeTab = async (key: string) => {
    const tab = tabs.find((t) => t.key === key)
    setTabs((prev) => prev.filter((t) => t.key !== key))
    setActiveKey((current) => {
      if (current !== key) return current
      const remaining = tabs.filter((t) => t.key !== key)
      return remaining.at(-1)?.key ?? null
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

  const shown = prefs.split ? tabs.slice(-2) : tabs.filter((t) => t.key === activeKey)

  const activeTab = tabs.find((t) => t.key === activeKey) ?? null

  return (
    <div className={'workspace' + (prefs.tree ? '' : ' collapsed')}>
      <aside className="sidebar" hidden={!prefs.tree}>
        <div className="sidebar-head">
          <input
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
                          onClick={() => setActiveKey(t.key)}>
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
          </div>
        )}

        {selected && (
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
              className={'tab' + (tab.key === activeKey ? ' active' : '')}
            >
              <button className="tab-label" onClick={() => setActiveKey(tab.key)}>
                {tab.label}
                {tab.ended && <span className="muted"> · ended</span>}
              </button>
              <button className="tab-close" aria-label={`Close ${tab.label}`}
                      onClick={() => void closeTab(tab.key)}>×</button>
            </div>
          ))}

          <div className="tabstrip-tools">
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
            onSaved={() => { setPanel({ kind: 'none' }); void loadTree() }}
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
                otherTerminals={live}
                onTerminalID={(id) => {
                  setTabs((prev) =>
                    prev.map((t) => (t.key === tab.key ? { ...t, terminalId: id } : t)))
                  void loadLive()
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
    }
  } catch {
    return DEFAULT_PREFS
  }
}
