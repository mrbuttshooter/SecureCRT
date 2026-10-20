import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError, api,
  type Folder, type LiveTerminal, type SavedSession, type Tree, type Whoami,
} from '../api'
import { SessionTree } from './SessionTree'
import { SessionEditor } from './SessionEditor'
import { FolderEditor } from './FolderEditor'
import { ConsoleServer } from './ConsoleServer'
import { TerminalPane } from '../terminal/TerminalPane'
import { SnippetBar } from '../terminal/SessionTools'
import { CommandWindow } from '../terminal/CommandWindow'
import { QuickConnect } from './QuickConnect'
import { FolderCredentialPicker } from './FolderCredentialPicker'
import { SettingsDialog } from './SettingsDialog'
import { SessionFinder, ShortcutSheet } from './SessionFinder'
import { ContextMenu, MENU_BREAK, type MenuItem } from '../ContextMenu'
import { MenuBar, SEPARATOR, WindowDialog, heading, type MenuDef } from '../Chrome'
import { useRovingToolbar } from './useRovingToolbar'
import { Icon } from '../Icon'
import { commandFor } from '../terminal/keys'
import { paneHandle, type PaneInfo } from '../terminal/panes'
import { appearanceFor } from '../terminal/appearance'
import { loadPrefs, savePrefs, type Layout, type Prefs } from '../terminal/prefs'

/** The windows that open from the menus, over the terminals. */
export type Page =
  | 'files' | 'tunnels' | 'snippets' | 'credentials' | 'hosts'
  | 'recordings' | 'transfer' | 'sessions' | 'security' | 'admin'

type Theme = 'dark' | 'light' | 'system'

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
  /** Output arrived while the tab was off screen. */
  activity?: boolean
  /** The host rang the bell while the tab was off screen. */
  bell?: boolean
}

type Panel =
  | { kind: 'none' }
  | { kind: 'session'; session: SavedSession | null; folderId: string }
  | { kind: 'folder'; folder: Folder | null; parentId: string }
  | { kind: 'console'; folderId: string }

type Dialog = 'none' | 'settings' | 'finder' | 'shortcuts' | 'quick'

/** Where the open tabs are remembered, so a reload can offer them back. */
const TABS_KEY = 'bkd.terminal.tabs'

export interface WorkspaceProps {
  /** False while a window from the menus is open on top. */
  active: boolean
  me: Whoami
  theme: Theme
  onTheme: (theme: Theme) => void
  onOpenPage: (page: Page) => void
  onLockVault: () => void
  onSignOut: () => void
}

/**
 * Workspace is the main window, laid out the way SecureCRT's is: a menu bar,
 * a toolbar, the Session Manager on the left, tabs and terminals on the
 * right, and a status bar along the bottom. Everything a person needs daily
 * is one click away on the toolbar; everything else is in a menu, where a
 * SecureCRT user will look for it.
 *
 * Tabs are never unmounted while they are open, only hidden. Unmounting would
 * dispose the xterm instance and throw away the scrollback the user can see —
 * the server would still hold the session, but the visible history would be
 * gone, which is not what "switch tab and back" should mean.
 */
export function Workspace(props: WorkspaceProps) {
  const { active } = props
  const [tree, setTree] = useState<Tree>({ folders: [], sessions: [] })
  const [live, setLive] = useState<LiveTerminal[]>([])
  const [tabs, setTabs] = useState<Tab[]>([])
  const [activeKey, setActiveKey] = useState<string | null>(null)
  const [selected, setSelected] = useState<SavedSession | null>(null)
  const [panel, setPanel] = useState<Panel>({ kind: 'none' })
  const [filter, setFilter] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs)
  const [dialog, setDialog] = useState<Dialog>('none')
  const [tabMenu, setTabMenu] = useState<{ x: number; y: number; key: string } | null>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  // Ctrl+click multi-selection in the tree, for bulk connect and delete.
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const dragTab = useRef<string | null>(null)
  const [folderCred, setFolderCred] = useState<Folder | null>(null)
  // Most-recently-active tab keys, newest first. Split mode shows the top
  // two, so what is on screen always includes the tab you last clicked.
  const [recency, setRecency] = useState<string[]>([])
  const nextKey = useRef(0)
  const restored = useRef(false)
  const filterInput = useRef<HTMLInputElement>(null)

  const patchPrefs = useCallback((patch: Partial<Prefs>) => {
    setPrefs((p) => ({ ...p, ...patch }))
  }, [])

  const focusTab = useCallback((key: string) => {
    setActiveKey(key)
    setRecency((prev) => [key, ...prev.filter((k) => k !== key)])
    // Looking at a tab is what reading its news means.
    setTabs((prev) => prev.some((t) => t.key === key && (t.activity || t.bell))
      ? prev.map((t) => (t.key === key ? { ...t, activity: false, bell: false } : t))
      : prev)
  }, [])

  useEffect(() => { savePrefs(prefs) }, [prefs])

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
      setTabs((prev) => [...revived, ...prev])
      const wanted = saved.tabs[saved.active ?? -1]?.terminalId
      const focus = revived.find((t) => t.terminalId === wanted) ?? revived.at(-1)!
      setActiveKey((current) => current ?? focus.key)
      setRecency((prev) => [...prev, ...revived.map((t) => t.key).reverse()])
      void loadLive()
    })()
  }, [loadLive])

  // Reloaded whenever this window comes back to the front — after an import,
  // the tree must show what was imported rather than look as empty as before.
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

  // The handful of connections used last — SecureCRT's recent-sessions list
  // in the File menu, which is how most days actually start.
  const recent = useMemo(
    () => tree.sessions
      .filter((s) => s.last_used_at)
      .sort((a, b) => Date.parse(b.last_used_at!) - Date.parse(a.last_used_at!))
      .slice(0, 6),
    [tree],
  )

  const openTab = (tab: Omit<Tab, 'key'>) => {
    const key = `tab-${nextKey.current++}`
    setTabs((prev) => [...prev, { ...tab, key }])
    focusTab(key)
  }

  const connect = (session: SavedSession) => {
    // A saved connection can be opened more than once — two windows onto the
    // same switch is normal — so this always opens a tab.
    openTab({ label: session.name, sessionId: session.id })
    void loadLive()
  }

  const reattach = (t: LiveTerminal) => {
    // The saved-connection id comes along so that when this terminal
    // eventually ends, the tab can still redial.
    openTab({ label: t.label || t.host, terminalId: t.id, sessionId: t.session_id })
  }

  /**
   * closeTabs closes one tab or several, deciding once what comes to the
   * front: the nearest surviving neighbour of the tab that was active, the
   * way every tabbed program behaves. Deciding per tab, from the same
   * snapshot, once left "Close the others" pointing at a closed tab.
   *
   * Closing a tab ends its session. An invisible SSH session holding a
   * device's vty line is exactly what people complain about.
   */
  const closeTabs = (keys: string[], confirmed = false) => {
    const gone = new Set(keys)
    const closing = tabs.filter((t) => gone.has(t.key))
    if (!closing.length) return
    const connected = closing.filter((t) => t.terminalId && !t.ended)
    if (!confirmed && prefs.confirmClose && connected.length > 0 && !window.confirm(
      connected.length === 1
        ? `“${connected[0]!.label}” is still connected. Close it and end the session?`
        : `${connected.length} tabs are still connected. Close and end them?`,
    )) return

    let next = activeKey
    if (activeKey && gone.has(activeKey)) {
      const at = tabs.findIndex((t) => t.key === activeKey)
      next = tabs.slice(at).find((t) => !gone.has(t.key))?.key
        ?? tabs.slice(0, at).reverse().find((t) => !gone.has(t.key))?.key
        ?? null
    }
    setTabs((prev) => prev.filter((t) => !gone.has(t.key)))
    setRecency((prev) => prev.filter((k) => !gone.has(k)))
    if (next !== activeKey) {
      if (next) focusTab(next)
      else setActiveKey(null)
    }

    void (async () => {
      for (const tab of closing) {
        if (!tab.terminalId) continue
        try {
          await api.delete(`/api/terminals/${tab.terminalId}`)
        } catch {
          // Already gone, most likely.
        }
      }
      void loadLive()
    })()
  }

  const closeTab = (key: string) => closeTabs([key])

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

  // What is on screen: the active tab; or it and the one used before it; or
  // every tab, tiled — SecureCRT's Tile, for watching a change go out
  // across a rack.
  const shown = prefs.layout === 'grid'
    ? tabs
    : prefs.layout === 'split'
      ? tabs.filter((t) => recency.slice(0, 2).includes(t.key))
      : tabs.filter((t) => t.key === activeKey)
  const columns = prefs.layout === 'grid'
    ? Math.min(4, Math.ceil(Math.sqrt(Math.max(1, tabs.length))))
    : prefs.layout === 'split' && shown.length > 1 ? 2 : 1

  const activeTab = tabs.find((t) => t.key === activeKey) ?? null
  const pane = () => paneHandle(activeKey)
  const activeSession = activeTab?.sessionId
    ? tree.sessions.find((s) => s.id === activeTab.sessionId) ?? null
    : null

  const renameTab = (key: string, label: string) => {
    const name = label.trim()
    if (name) setTabs((prev) => prev.map((t) => (t.key === key ? { ...t, label: name } : t)))
    setRenaming(null)
  }

  const showTree = () => {
    if (!prefs.tree) patchPrefs({ tree: true })
    window.setTimeout(() => filterInput.current?.focus(), 0)
  }

  const step = (by: 1 | -1) => {
    if (tabs.length < 2) return
    const at = Math.max(0, tabs.findIndex((t) => t.key === activeKey))
    focusTab(tabs[(at + (by === 1 ? 1 : tabs.length - 1)) % tabs.length]!.key)
  }

  const cycleLayout = () => {
    const order: Layout[] = ['single', 'split', 'grid']
    patchPrefs({ layout: order[(order.indexOf(prefs.layout) + 1) % order.length]! })
  }

  // The chords the panes claim from xterm bubble up to here; this listener
  // is also what makes them work when focus is in the tree or the filter.
  useEffect(() => {
    if (!active) return
    const onKey = (event: KeyboardEvent) => {
      const command = commandFor(event)
      if (!command) return
      const p = pane()
      switch (command.kind) {
        case 'jump': {
          const target = tabs[command.index]
          if (target) { event.preventDefault(); focusTab(target.key) }
          break
        }
        case 'next-tab':
        case 'prev-tab':
          event.preventDefault()
          step(command.kind === 'next-tab' ? 1 : -1)
          break
        case 'quick-connect':
          event.preventDefault()
          setDialog((d) => (d === 'quick' ? 'none' : 'quick'))
          break
        case 'filter':
          event.preventDefault()
          showTree()
          break
        case 'close-tab':
          if (activeKey) { event.preventDefault(); void closeTab(activeKey) }
          break
        case 'duplicate-tab':
          if (activeTab?.sessionId) {
            event.preventDefault()
            openTab({ label: activeTab.label, sessionId: activeTab.sessionId })
          }
          break
        case 'finder':
          event.preventDefault()
          setDialog((d) => (d === 'finder' ? 'none' : 'finder'))
          break
        case 'settings':
          event.preventDefault()
          setDialog((d) => (d === 'settings' ? 'none' : 'settings'))
          break
        case 'shortcuts':
          event.preventDefault()
          setDialog((d) => (d === 'shortcuts' ? 'none' : 'shortcuts'))
          break
        case 'command-window':
          event.preventDefault()
          if (prefs.commandWindow) p?.focus()
          patchPrefs({ commandWindow: !prefs.commandWindow })
          break
        case 'layout':
          event.preventDefault()
          cycleLayout()
          break
        // The rest act on the pane in front, wherever focus happens to be.
        case 'find':
          if (p) { event.preventDefault(); p.find() }
          break
        case 'broadcast':
          if (p) { event.preventDefault(); p.broadcastMenu() }
          break
        case 'zoom':
          if (p) { event.preventDefault(); p.zoom(command.step) }
          break
        case 'fullscreen':
          if (p) { event.preventDefault(); p.fullscreen() }
          break
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  })

  // --- the menu bar ----------------------------------------------------------

  const noPane = !activeTab
  const notLive = !activeTab || Boolean(activeTab.ended) || !activeTab.terminalId
  const endedCount = tabs.filter((t) => t.ended && t.sessionId).length
  const isAdmin = props.me.user.is_admin

  const menus: MenuDef[] = [
    {
      label: 'File',
      items: [
        { label: 'Connect…', shortcut: 'Ctrl+Shift+Space', onClick: () => setDialog('finder') },
        { label: 'Quick Connect…', shortcut: 'Ctrl+Shift+Q', onClick: () => setDialog('quick') },
        SEPARATOR,
        { label: 'New connection…', onClick: () => setPanel({ kind: 'session', session: null, folderId: '' }) },
        { label: 'New folder…', onClick: () => setPanel({ kind: 'folder', folder: null, parentId: '' }) },
        { label: 'Console server…', onClick: () => setPanel({ kind: 'console', folderId: '' }) },
        ...(recent.length > 0
          ? [SEPARATOR, ...recent.map((s, i) => ({ label: `${i + 1}  ${s.name}`, onClick: () => connect(s) }))]
          : []),
        SEPARATOR,
        { label: 'Import and export…', onClick: () => props.onOpenPage('transfer') },
        SEPARATOR,
        { label: 'Lock vault', onClick: props.onLockVault },
        { label: 'Sign out', onClick: props.onSignOut },
      ],
    },
    {
      label: 'Edit',
      items: [
        { label: 'Copy', disabled: noPane, onClick: () => pane()?.copy() },
        { label: 'Paste', disabled: notLive, onClick: () => pane()?.pasteClipboard() },
        { label: 'Select all', disabled: noPane, onClick: () => pane()?.selectAll() },
        SEPARATOR,
        { label: 'Find…', shortcut: 'Ctrl+Shift+F', disabled: noPane, onClick: () => pane()?.find() },
        { label: 'Filter connections', shortcut: 'Ctrl+Shift+K', onClick: showTree },
        SEPARATOR,
        { label: 'Clear scrollback', disabled: noPane, onClick: () => pane()?.clear() },
        { label: 'Reset terminal', disabled: noPane, onClick: () => pane()?.reset() },
      ],
    },
    {
      label: 'View',
      items: [
        { label: 'Session Manager', checked: prefs.tree, onClick: () => patchPrefs({ tree: !prefs.tree }) },
        {
          label: 'Command window', shortcut: 'Ctrl+Shift+Enter', checked: prefs.commandWindow,
          onClick: () => patchPrefs({ commandWindow: !prefs.commandWindow }),
        },
        SEPARATOR,
        heading('Layout'),
        { label: 'One terminal', radio: true, checked: prefs.layout === 'single', onClick: () => patchPrefs({ layout: 'single' }) },
        { label: 'Two side by side', radio: true, checked: prefs.layout === 'split', onClick: () => patchPrefs({ layout: 'split' }) },
        { label: 'Tile all terminals', shortcut: 'Ctrl+Shift+L', radio: true, checked: prefs.layout === 'grid', onClick: () => patchPrefs({ layout: 'grid' }) },
        SEPARATOR,
        { label: 'Bigger text', shortcut: 'Ctrl+Shift+=', disabled: noPane, onClick: () => pane()?.zoom(1) },
        { label: 'Smaller text', shortcut: 'Ctrl+Shift+-', disabled: noPane, onClick: () => pane()?.zoom(-1) },
        { label: 'Normal text size', shortcut: 'Ctrl+Shift+0', disabled: noPane, onClick: () => pane()?.zoom(0) },
        { label: 'Full screen', shortcut: 'Alt+Enter', disabled: noPane, onClick: () => pane()?.fullscreen() },
        SEPARATOR,
        heading('Window colours'),
        { label: 'Light', radio: true, checked: props.theme === 'light', onClick: () => props.onTheme('light') },
        { label: 'Dark', radio: true, checked: props.theme === 'dark', onClick: () => props.onTheme('dark') },
        { label: 'Follow Windows', radio: true, checked: props.theme === 'system', onClick: () => props.onTheme('system') },
      ],
    },
    {
      label: 'Options',
      items: [
        { label: 'Terminal settings…', shortcut: 'Ctrl+Shift+,', onClick: () => setDialog('settings') },
        {
          label: 'Session options…', disabled: !activeSession,
          onClick: () => activeSession && setPanel({ kind: 'session', session: activeSession, folderId: activeSession.folder_id }),
        },
        SEPARATOR,
        { label: 'Ask before pasting several lines', checked: prefs.pasteGuard, onClick: () => patchPrefs({ pasteGuard: !prefs.pasteGuard }) },
        { label: 'Reconnect automatically', checked: prefs.autoReconnect, onClick: () => patchPrefs({ autoReconnect: !prefs.autoReconnect }) },
        { label: 'Ask before closing a connected tab', checked: prefs.confirmClose, onClick: () => patchPrefs({ confirmClose: !prefs.confirmClose }) },
      ],
    },
    {
      label: 'Transfer',
      items: [
        { label: 'File transfer (SFTP)…', onClick: () => props.onOpenPage('files') },
        { label: 'Save output to a file', disabled: noPane, onClick: () => pane()?.saveOutput() },
        SEPARATOR,
        { label: 'Import and export…', onClick: () => props.onOpenPage('transfer') },
      ],
    },
    {
      label: 'Tools',
      items: [
        { label: 'Send a snippet…', disabled: notLive, onClick: () => pane()?.snippetsMenu() },
        { label: 'Broadcast to other terminals…', shortcut: 'Ctrl+Shift+B', disabled: notLive, onClick: () => pane()?.broadcastMenu() },
        { label: 'Start or stop recording', disabled: notLive, onClick: () => pane()?.toggleRecording() },
        SEPARATOR,
        { label: 'Snippets and button bar…', onClick: () => props.onOpenPage('snippets') },
        { label: 'Transcripts…', onClick: () => props.onOpenPage('recordings') },
        { label: 'Port forwarding and tunnels…', onClick: () => props.onOpenPage('tunnels') },
        SEPARATOR,
        { label: 'Credentials: keys and passwords…', onClick: () => props.onOpenPage('credentials') },
        { label: 'Known hosts…', onClick: () => props.onOpenPage('hosts') },
      ],
    },
    {
      label: 'Window',
      items: [
        { label: 'Next tab', shortcut: 'Alt+PgDn', disabled: tabs.length < 2, onClick: () => step(1) },
        { label: 'Previous tab', shortcut: 'Alt+PgUp', disabled: tabs.length < 2, onClick: () => step(-1) },
        ...(tabs.length > 0 ? [SEPARATOR] : []),
        ...tabs.slice(0, 20).map((t, i) => ({
          label: t.label + (t.ended ? ' (ended)' : ''),
          shortcut: i < 9 ? `Alt+${i + 1}` : undefined,
          checked: t.key === activeKey,
          onClick: () => focusTab(t.key),
        })),
        SEPARATOR,
        {
          label: 'Duplicate tab', shortcut: 'Ctrl+Shift+D', disabled: !activeTab?.sessionId,
          onClick: () => activeTab?.sessionId && openTab({ label: activeTab.label, sessionId: activeTab.sessionId }),
        },
        {
          label: endedCount > 1 ? `Reconnect all ${endedCount} ended tabs` : 'Reconnect all ended tabs',
          disabled: endedCount === 0,
          onClick: () => window.dispatchEvent(new CustomEvent('bkd:reconnect-all')),
        },
        { label: 'Close tab', shortcut: 'Ctrl+Shift+X', disabled: noPane, onClick: () => activeKey && void closeTab(activeKey) },
        { label: 'Close all tabs', disabled: tabs.length === 0, onClick: () => closeTabs(tabs.map((t) => t.key)) },
      ],
    },
    {
      label: 'Help',
      items: [
        { label: 'Keyboard shortcuts', shortcut: 'Ctrl+Shift+/', onClick: () => setDialog('shortcuts') },
        SEPARATOR,
        { label: 'Security and two-factor…', onClick: () => props.onOpenPage('security') },
        { label: 'Sign-ins…', onClick: () => props.onOpenPage('sessions') },
        ...(isAdmin ? [{ label: 'Administration…', onClick: () => props.onOpenPage('admin') }] : []),
      ],
    },
  ]

  // Everything a right-click on a tab offers.
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
      { label: 'Rename…', onClick: () => setRenaming(key) },
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
      ...(tab.sessionId
        ? [{
            label: 'Session options…',
            onClick: () => {
              const session = tree.sessions.find((s) => s.id === tab.sessionId)
              if (session) setPanel({ kind: 'session', session, folderId: session.folder_id })
            },
          }]
        : []),
      MENU_BREAK,
      { label: 'Close', danger: true, onClick: () => void closeTab(key) },
      {
        label: 'Close the others',
        danger: true,
        disabled: tabs.length < 2,
        onClick: () => closeTabs(tabs.filter((t) => t.key !== key).map((t) => t.key)),
      },
      {
        label: 'Close to the right',
        danger: true,
        disabled: at === tabs.length - 1,
        onClick: () => closeTabs(tabs.slice(at + 1).map((t) => t.key)),
      },
    ]
  }

  const toolbarRef = useRef<HTMLDivElement>(null)
  useRovingToolbar(toolbarRef)

  /**
   * One toolbar button. The name is short, for screen readers and the
   * tooltip's first line; the shortcut is announced and shown alongside.
   * Mouse-down does not take focus, so clicking Paste leaves the keyboard
   * in the terminal and the next Enter goes to the host, not to Paste again.
   */
  const tool = (icon: string, name: string, onClick: () => void, opts: {
    shortcut?: string; text?: boolean; disabled?: boolean; pressed?: boolean
  } = {}) => (
    <button
      className={'tb' + (opts.pressed ? ' pressed' : '')}
      data-icon={icon}
      title={opts.shortcut ? `${name} (${opts.shortcut})` : name}
      aria-label={name}
      aria-keyshortcuts={opts.shortcut?.replace(/Ctrl/g, 'Control')}
      aria-pressed={opts.pressed}
      disabled={opts.disabled}
      onMouseDown={(e) => e.preventDefault()}
      onClick={onClick}
    >
      <Icon name={icon} />
      {opts.text && <span>{name}</span>}
    </button>
  )

  const panelTitle = panel.kind === 'session'
    ? (panel.session ? `Session options: ${panel.session.name}` : 'New connection')
    : panel.kind === 'folder'
      ? (panel.folder ? `Folder: ${panel.folder.name}` : 'New folder')
      : 'Console server'

  return (
    <div className="mainwin">
      <MenuBar
        menus={menus}
        start={<span className="menubar-mark" aria-hidden="true"><Icon name="connect" /></span>}
        end={
          <span className="menubar-user" title={props.me.user.email + (isAdmin ? ' · administrator' : '')}>
            {props.me.user.display_name || props.me.user.email}
          </span>
        }
      />

      <div className="toolbar" role="toolbar" aria-label="Toolbar" ref={toolbarRef}>
        {tool('connect', 'Connect', () => setDialog('finder'), { text: true, shortcut: 'Ctrl+Shift+Space' })}
        {tool('quick', 'Quick Connect', () => setDialog('quick'), { text: true, shortcut: 'Ctrl+Shift+Q' })}
        <span className="tb-sep" role="separator" />
        {tool('reconnect', 'Reconnect', () => pane()?.reconnect(), { disabled: !activeTab?.ended })}
        {tool('disconnect', 'Disconnect', () => activeKey && void closeTab(activeKey), { disabled: noPane, shortcut: 'Ctrl+Shift+X' })}
        <span className="tb-sep" role="separator" />
        {tool('copy', 'Copy', () => pane()?.copy(), { disabled: noPane })}
        {tool('paste', 'Paste', () => pane()?.pasteClipboard(), { disabled: notLive })}
        {tool('find', 'Find', () => pane()?.find(), { disabled: noPane, shortcut: 'Ctrl+Shift+F' })}
        <span className="tb-sep" role="separator" />
        {tool('options', 'Session options', () =>
          activeSession && setPanel({ kind: 'session', session: activeSession, folderId: activeSession.folder_id }),
          { disabled: !activeSession })}
        {tool('settings', 'Terminal settings', () => setDialog('settings'), { shortcut: 'Ctrl+Shift+,' })}
        <span className="tb-sep" role="separator" />
        {tool('files', 'File transfer (SFTP)', () => props.onOpenPage('files'))}
        {tool('snippets', 'Send a snippet', () => pane()?.snippetsMenu(), { disabled: notLive })}
        {tool('broadcast', 'Broadcast', () => pane()?.broadcastMenu(), { disabled: notLive, shortcut: 'Ctrl+Shift+B' })}
        <span className="tb-sep" role="separator" />
        <span role="group" aria-label="Layout" className="tb-group">
          {tool('single', 'One terminal', () => patchPrefs({ layout: 'single' }), { pressed: prefs.layout === 'single' })}
          {tool('split', 'Two side by side', () => patchPrefs({ layout: 'split' }), { pressed: prefs.layout === 'split' })}
          {tool('grid', 'Tile all terminals', () => patchPrefs({ layout: 'grid' }), { pressed: prefs.layout === 'grid', shortcut: 'Ctrl+Shift+L' })}
        </span>
        <span className="tb-sep" role="separator" />
        {tool('command', 'Command window', () => patchPrefs({ commandWindow: !prefs.commandWindow }), { pressed: prefs.commandWindow, shortcut: 'Ctrl+Shift+Enter' })}
        {tool('sidebar', 'Session Manager', () => patchPrefs({ tree: !prefs.tree }), { pressed: prefs.tree })}
      </div>

      <div className={'workspace' + (prefs.tree ? '' : ' collapsed')}>
        <aside className="sidebar" hidden={!prefs.tree} aria-label="Session Manager">
          <div className="sm-head">
            <span className="sm-title">Session Manager</span>
            <span className="sm-tools">
              <button className="tb small" title="New connection" aria-label="New connection"
                      onClick={() => setPanel({ kind: 'session', session: null, folderId: '' })}>
                <Icon name="new-session" />
              </button>
              <button className="tb small" title="New folder" aria-label="New folder"
                      onClick={() => setPanel({ kind: 'folder', folder: null, parentId: '' })}>
                <Icon name="new-folder" />
              </button>
              <button className="tb small" title="Console server: one folder of lines" aria-label="Console server"
                      onClick={() => setPanel({ kind: 'console', folderId: '' })}>
                <Icon name="console" />
              </button>
              <button className="tb small" title="Hide the Session Manager" aria-label="Hide the Session Manager"
                      onClick={() => patchPrefs({ tree: false })}>
                <Icon name="close" />
              </button>
            </span>
          </div>
          <div className="sm-filter">
            <input
              ref={filterInput}
              className="filter"
              aria-label="Filter connections"
              placeholder="Filter sessions"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>

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
            teamName={(id) => (tree.teams ?? []).find((t) => t.id === id)?.name ?? 'shared'}
            onFolderCredential={(folder) => setFolderCred(folder)}
          />

          {orphans.length > 0 && (
            <div className="orphans">
              <h3>Still running</h3>
              <p className="muted">Sessions left open in another browser.</p>
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
                <button className="link" onClick={() => orphans.forEach((t) => reattach(t))}>
                  Reattach all {orphans.length}
                </button>
              )}
            </div>
          )}

          {checked.size > 1 && (
            <div className="selection">
              <h3>{checked.size} selected</h3>
              <div className="row">
                <button onClick={() => {
                  const picked = tree.sessions.filter((s) => checked.has(s.id))
                  if (picked.length <= 5 || window.confirm(
                    `Open ${picked.length} terminals, one per selected connection?`)) {
                    picked.forEach((s) => connect(s))
                  }
                }}>
                  Connect all
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
                  Delete
                </button>
              </div>
            </div>
          )}
        </aside>

        <section className="terminals">
          {tabs.length > 0 && (
            <div className="tabstrip" role="group" aria-label="Open sessions">
              {tabs.map((tab, index) => (
                <div
                  key={tab.key}
                  className={'tab' + (tab.key === activeKey ? ' active' : '')
                    + (tab.colour !== undefined ? ` tab-c${tab.colour}` : '')
                    + (tab.activity ? ' has-activity' : '')
                    + (tab.bell ? ' has-bell' : '')}
                  title={index < 9 ? `Alt+${index + 1} · double-click to rename` : 'Double-click to rename'}
                  onContextMenu={(e) => {
                    e.preventDefault()
                    setTabMenu({ x: e.clientX, y: e.clientY, key: tab.key })
                  }}
                  onAuxClick={(e) => {
                    // Middle-click closes, as it does on every browser tab.
                    if (e.button === 1) { e.preventDefault(); void closeTab(tab.key) }
                  }}
                  draggable={renaming !== tab.key}
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
                  {renaming === tab.key ? (
                    <input
                      className="tab-rename"
                      aria-label="Tab name"
                      autoFocus
                      defaultValue={tab.label}
                      onFocus={(e) => e.currentTarget.select()}
                      onBlur={(e) => renameTab(tab.key, e.currentTarget.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') renameTab(tab.key, e.currentTarget.value)
                        if (e.key === 'Escape') setRenaming(null)
                      }}
                    />
                  ) : (
                    <button className="tab-label" onClick={() => focusTab(tab.key)}
                            aria-current={tab.key === activeKey ? 'true' : undefined}
                            aria-keyshortcuts={index < 9 ? `Alt+${index + 1}` : undefined}
                            onDoubleClick={() => setRenaming(tab.key)}>
                      {tab.label}
                    </button>
                  )}
                  {tab.bell && <span className="bell-mark" title="The host rang the bell">{'♪'}</span>}
                  <button className="tab-close" aria-label={`Close ${tab.label}`}
                          onClick={() => void closeTab(tab.key)}>×</button>
                </div>
              ))}
            </div>
          )}

          {error && (
            <div className="error">
              {error} <button className="link" onClick={() => setError(null)}>Dismiss</button>
            </div>
          )}

          <div className={`panes layout-${prefs.layout} cols-${columns}`}>
            {tabs.map((tab) => {
              const look = appearanceFor(tree, tab.sessionId)
              const isShown = shown.some((s) => s.key === tab.key)
              return (
                <div
                  key={tab.key}
                  className={'pane-slot' + (prefs.layout !== 'single' && tab.key === activeKey ? ' focused' : '')}
                  hidden={!isShown}
                  onMouseDown={() => { if (tab.key !== activeKey) focusTab(tab.key) }}
                >
                  <TerminalPane
                    paneKey={tab.key}
                    sessionId={tab.sessionId}
                    terminalId={tab.terminalId}
                    label={tab.label}
                    theme={look.theme ?? prefs.theme}
                    fontSize={look.fontSize ?? prefs.fontSize}
                    fontFamily={prefs.fontFamily}
                    scrollback={prefs.scrollback}
                    cursorStyle={prefs.cursorStyle}
                    cursorBlink={prefs.cursorBlink}
                    active={tab.key === activeKey}
                    compact={prefs.layout === 'single'}
                    pasteGuard={prefs.pasteGuard}
                    lineDelayMs={prefs.lineDelayMs}
                    copyOnSelect={prefs.copyOnSelect}
                    rightClickPaste={prefs.rightClickPaste}
                    bell={prefs.bell}
                    autoReconnect={prefs.autoReconnect}
                    otherTerminals={live}
                    onTerminalID={(id) => {
                      // A fresh terminal id also means a successful redial.
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
                    onActivity={() => {
                      // Only news when the tab is out of sight.
                      if (isShown) return
                      setTabs((prev) => prev.some((t) => t.key === tab.key && !t.activity)
                        ? prev.map((t) => (t.key === tab.key ? { ...t, activity: true } : t))
                        : prev)
                    }}
                    onBell={() => {
                      if (isShown) return
                      setTabs((prev) => prev.some((t) => t.key === tab.key && !t.bell)
                        ? prev.map((t) => (t.key === tab.key ? { ...t, bell: true } : t))
                        : prev)
                    }}
                  />
                </div>
              )
            })}

            {tabs.length === 0 && (
              <div className="welcome">
                <h2>No session open</h2>
                <p className="muted">
                  Double-click a session in the Session Manager, or:
                </p>
                <div className="row welcome-actions">
                  <button className="primary" onClick={() => setDialog('finder')}>
                    <Icon name="connect" /> Connect…
                  </button>
                  <button onClick={() => setDialog('quick')}>
                    <Icon name="quick" /> Quick Connect…
                  </button>
                  <button onClick={() => setPanel({ kind: 'session', session: null, folderId: '' })}>
                    <Icon name="new-session" /> New session…
                  </button>
                </div>
                {recent.length > 0 && (
                  <>
                    <h3>Recent sessions</h3>
                    <ul className="welcome-recent">
                      {recent.map((s) => (
                        <li key={s.id}>
                          <button className="link" onClick={() => connect(s)}>{s.name}</button>
                          <span className="muted mono">
                            {s.username ? s.username + '@' : ''}{s.hostname}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </div>

          {prefs.commandWindow && tabs.length > 0 && (
            <CommandWindow
              activeKey={activeTab && !activeTab.ended ? activeTab.key : null}
              label={activeTab?.label ?? null}
              onClose={() => patchPrefs({ commandWindow: false })}
            />
          )}

          {tabs.length > 0 && (
            <SnippetBar terminalId={activeTab && !activeTab.ended ? activeTab.terminalId ?? null : null} />
          )}
        </section>
      </div>

      <StatusBar
        tab={activeTab}
        terminal={live.find((t) => t.id === activeTab?.terminalId) ?? null}
      />

      {tabMenu && (
        <ContextMenu
          x={tabMenu.x}
          y={tabMenu.y}
          items={tabMenuItems(tabMenu.key)}
          onClose={() => setTabMenu(null)}
        />
      )}

      {panel.kind !== 'none' && (
        <WindowDialog title={panelTitle} onClose={() => setPanel({ kind: 'none' })}>
          {panel.kind === 'session' && (
            <SessionEditor
              key={panel.session?.id ?? 'new'}
              session={panel.session}
              folderId={panel.folderId}
              onSaved={(saved, connectNow) => {
                setPanel({ kind: 'none' })
                void loadTree()
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
              key={panel.folder?.id ?? 'new'}
              folder={panel.folder}
              parentId={panel.parentId}
              publishTeams={tree.teams}
              onSaved={() => { setPanel({ kind: 'none' }); void loadTree() }}
              onCancel={() => setPanel({ kind: 'none' })}
            />
          )}
        </WindowDialog>
      )}

      {folderCred && (
        <FolderCredentialPicker folder={folderCred} onClose={() => setFolderCred(null)} />
      )}

      {dialog === 'quick' && (
        <WindowDialog title="Quick Connect" onClose={() => setDialog('none')}>
          <p className="muted">
            Type <span className="mono">user@host:port</span> and press Enter. The
            session is saved under the Quick connect folder, so it is there next time.
          </p>
          <QuickConnect
            tree={tree}
            focusSignal={1}
            onConnected={(session) => { setDialog('none'); connect(session) }}
            onTreeChanged={() => void loadTree()}
          />
        </WindowDialog>
      )}

      {dialog === 'settings' && (
        <SettingsDialog prefs={prefs} onChange={patchPrefs} onClose={() => setDialog('none')} />
      )}

      {dialog === 'finder' && (
        <SessionFinder
          tree={tree}
          tabs={tabs}
          onConnect={connect}
          onFocusTab={focusTab}
          onClose={() => setDialog('none')}
        />
      )}

      {dialog === 'shortcuts' && <ShortcutSheet onClose={() => setDialog('none')} />}
    </div>
  )
}

const PROTOCOL_LABELS: Record<string, string> = { ssh: 'SSH2', telnet: 'Telnet', serial: 'Serial' }

/**
 * StatusBar is the strip along the bottom of SecureCRT's window: what the
 * session in front is, where it goes, how big the screen is. The pane facts
 * that used to crowd every terminal's own header live here once instead.
 */
function StatusBar({ tab, terminal }: {
  tab: { key: string; ended?: string; terminalId?: string } | null
  terminal: LiveTerminal | null
}) {
  const [info, setInfo] = useState<PaneInfo | null>(null)

  // The pane's size and state change without telling the workspace; a slow
  // tick is plenty for a status bar.
  useEffect(() => {
    // Only a real change re-renders: the bar is polled, and most polls
    // find nothing new.
    const read = () => {
      const next = paneHandle(tab?.key)?.info() ?? null
      setInfo((prev) => (JSON.stringify(prev) === JSON.stringify(next) ? prev : next))
    }
    read()
    const id = window.setInterval(read, 700)
    return () => window.clearInterval(id)
  }, [tab?.key])

  if (!tab) {
    return (
      <div className="statusbar" role="group" aria-label="Status">
        <span className="sb-cell grow">Ready</span>
      </div>
    )
  }

  const state = tab.ended ? 'ended' : info?.state ?? 'opening'
  const stateText = state === 'live' ? 'Ready'
    : state === 'ended' ? 'Disconnected — press Enter to reconnect'
    : state === 'reconnecting' ? 'Reconnecting…'
    : state === 'prompting' ? 'Waiting for you'
    : 'Connecting…'
  const where = terminal
    ? (terminal.protocol === 'serial'
      ? terminal.device ?? terminal.host
      : `${terminal.username ? terminal.username + '@' : ''}${terminal.host}:${terminal.port}`)
    : ''

  return (
    <div className="statusbar" role="group" aria-label="Status">
      {/* Only the state is announced; the size and scroll position change
          too often to be read aloud every time. */}
      <span className="sr-only" role="status">
        {state === 'live' ? 'Connected' : stateText}
        {terminal && !terminal.encrypted ? '. Not encrypted' : ''}
      </span>
      <span className={'sb-cell grow sb-state sb-' + state} aria-hidden="true">{stateText}</span>
      {terminal && <span className="sb-cell">{PROTOCOL_LABELS[terminal.protocol] ?? terminal.protocol}</span>}
      {where && <span className="sb-cell mono">{where}</span>}
      {terminal && !terminal.encrypted && <span className="sb-cell sb-warn">Not encrypted</span>}
      {info?.recorded && <span className="sb-cell sb-rec">REC</span>}
      {info && info.linesBack > 0 && <span className="sb-cell">{info.linesBack} lines up</span>}
      {info?.zoomedSize && <span className="sb-cell">{info.zoomedSize}px</span>}
      {info && info.cols > 0 && <span className="sb-cell">{info.rows} Rows, {info.cols} Cols</span>}
      <span className="sb-cell">Xterm</span>
    </div>
  )
}
