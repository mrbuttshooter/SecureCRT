import { useMemo, useState } from 'react'
import type { Folder, SavedSession, Tree } from '../api'
import { ContextMenu, MENU_BREAK, type MenuItem } from '../ContextMenu'
import './tree.css'

export interface SessionTreeProps {
  tree: Tree
  /** Which saved connections have a live terminal, by saved-connection ID. */
  liveSessionIds: Set<string>
  selectedId: string | null
  filter: string
  onOpen: (session: SavedSession) => void
  onSelect: (session: SavedSession) => void
  onEditFolder: (folder: Folder) => void
  onDeleteFolder: (folder: Folder) => void
  onNewSessionIn: (folderId: string) => void
  onNewFolderIn: (folderId: string) => void
  onEditSession: (session: SavedSession) => void
  onDeleteSession: (session: SavedSession) => void
  /** Ctrl+click multi-selection, owned by the workspace. */
  checkedIds: Set<string>
  onToggleCheck: (session: SavedSession) => void
  /** Names a team by id, for the shared-folder badge. */
  teamName: (id: string) => string
  /** Open the per-user credential picker for a shared folder. */
  onFolderCredential: (folder: Folder) => void
  /** Move an item to a folder. Empty destination means the top level. */
  onMove: (kind: 'folder' | 'session', id: string, destinationFolderId: string) => void
}

interface Node {
  folder: Folder
  children: Node[]
  sessions: SavedSession[]
}

/** ROOT is the sentinel the server uses for "no parent". */
const ROOT = ''

/**
 * SessionTree renders folders and saved connections.
 *
 * Two behaviours are worth stating because they are what makes the list
 * usable at the scale this is built for:
 *
 * Filtering shows a matching connection wherever it is, and keeps its
 * ancestors visible so the path stays legible. Searching a tree that then
 * collapses the context is worse than not searching.
 *
 * Dragging moves rather than copies, and a folder cannot be dropped into its
 * own descendant — the server refuses that too, but refusing it here means
 * the drop is simply not offered rather than failing after the fact.
 */
export function SessionTree(props: SessionTreeProps) {
  const { tree, filter } = props
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [dragging, setDragging] = useState<{ kind: 'folder' | 'session'; id: string } | null>(null)
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null)
  const [dropTarget, setDropTarget] = useState<string | null>(null)

  const roots = useMemo(() => buildTree(tree), [tree])
  const needle = filter.trim().toLowerCase()

  // Descendants of the folder being dragged, so it cannot be dropped inside
  // itself. Computed once per drag rather than per candidate row.
  const forbidden = useMemo(() => {
    if (dragging?.kind !== 'folder') return new Set<string>()
    const out = new Set<string>([dragging.id])
    let grew = true
    while (grew) {
      grew = false
      for (const f of tree.folders) {
        if (!out.has(f.id) && out.has(f.parent_id)) {
          out.add(f.id)
          grew = true
        }
      }
    }
    return out
  }, [dragging, tree.folders])

  const toggle = (id: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const dropInto = (folderId: string) => {
    if (dragging && !forbidden.has(folderId)) {
      props.onMove(dragging.kind, dragging.id, folderId)
    }
    setDragging(null)
    setDropTarget(null)
  }

  const renderSession = (s: SavedSession, depth: number) => {
    const live = props.liveSessionIds.has(s.id)
    return (
      <li
        key={s.id}
        className={
          'tree-row tree-session' +
          (props.selectedId === s.id ? ' selected' : '') +
          (props.checkedIds.has(s.id) ? ' checked' : '') +
          (live ? ' live' : '')
        }
        // No twisty on a connection: the extra indent lines its icon up one
        // level in from its folder's icon, the way Explorer does it.
        style={{ paddingLeft: `${depth * INDENT + 2 + TWISTY}px` }}
        draggable
        onDragStart={() => setDragging({ kind: 'session', id: s.id })}
        onDragEnd={() => { setDragging(null); setDropTarget(null) }}
        onContextMenu={(e) => {
          e.preventDefault()
          props.onSelect(s)
          setMenu({ ...menuAt(e), items: [
            { label: 'Connect', onClick: () => props.onOpen(s) },
            { label: 'Edit…', onClick: () => props.onEditSession(s) },
            MENU_BREAK,
            { label: 'Delete…', danger: true, onClick: () => props.onDeleteSession(s) },
          ] })
        }}
      >
        <button
          className="tree-label"
          // The row shows a status icon and the hostname alongside the name,
          // which would otherwise all end up in the accessible name and make
          // every row read as a sentence. The name is what identifies it.
          aria-label={live ? `${s.name} (connected)` : s.name}
          onClick={(e) => {
            // Ctrl+click gathers; a plain click selects, the way the file
            // browser next door already behaves.
            if (e.ctrlKey || e.metaKey) props.onToggleCheck(s)
            else props.onSelect(s)
          }}
          onDoubleClick={() => props.onOpen(s)}
          onKeyDown={(e) => {
            // Enter connects, as in SecureCRT's Session Manager; Space still
            // selects. With the row's Connect link gone this is the keyboard
            // path to it, besides the context-menu key.
            if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey && !e.altKey) {
              e.preventDefault()
              props.onSelect(s)
              props.onOpen(s)
            }
          }}
          title={`${s.username ? s.username + '@' : ''}${s.hostname}:${s.effective_port}`}
        >
          <span className="tree-icon" aria-hidden="true">
            <SessionIcon />
            {live && <span className="tree-live-dot" />}
          </span>
          <span className="tree-name">{s.name}</span>
          {!s.name.includes(s.hostname) && (
            <span className="tree-host muted">{s.hostname}</span>
          )}
        </button>
      </li>
    )
  }

  const renderNode = (node: Node, depth: number): React.ReactNode => {
    const matching = filterNode(node, needle)
    if (!matching) return null

    const isCollapsed = collapsed.has(node.folder.id) && !needle
    const canDrop = dragging !== null && !forbidden.has(node.folder.id)

    return (
      <li key={node.folder.id} className="tree-branch">
        <div
          className={
            'tree-row tree-folder' +
            (dropTarget === node.folder.id && canDrop ? ' drop-target' : '')
          }
          style={{ paddingLeft: `${depth * INDENT + 2}px` }}
          draggable
          onDragStart={() => setDragging({ kind: 'folder', id: node.folder.id })}
          onDragEnd={() => { setDragging(null); setDropTarget(null) }}
          onDragOver={(e) => {
            if (!canDrop) return
            e.preventDefault()
            setDropTarget(node.folder.id)
          }}
          onDragLeave={() => setDropTarget((t) => (t === node.folder.id ? null : t))}
          onDrop={(e) => { e.preventDefault(); dropInto(node.folder.id) }}
          onDoubleClick={(e) => {
            // Double-clicking a folder opens or closes it, as in Explorer.
            // The twisty already toggles on each of its own clicks.
            if (!(e.target as HTMLElement).closest('.tree-twisty')) toggle(node.folder.id)
          }}
          onContextMenu={(e) => {
            e.preventDefault()
            const inside = sessionsUnder(node)
            setMenu({ ...menuAt(e), items: [
              { label: 'New connection here…', onClick: () => props.onNewSessionIn(node.folder.id) },
              { label: 'New folder here…', onClick: () => props.onNewFolderIn(node.folder.id) },
              { label: 'Folder defaults…', onClick: () => props.onEditFolder(node.folder) },
              ...(node.folder.team_id
                ? [{ label: 'My credential for this rack…',
                     onClick: () => props.onFolderCredential(node.folder) }]
                : []),
              MENU_BREAK,
              {
                label: `Connect all ${inside.length}`,
                disabled: inside.length === 0,
                onClick: () => {
                  // A rack can be forty-eight lines; a misplaced click must
                  // not open forty-eight sessions unasked.
                  if (inside.length <= 5 || window.confirm(
                    `Open ${inside.length} terminals, one per connection in “${node.folder.name}”?`,
                  )) inside.forEach((s) => props.onOpen(s))
                },
              },
              MENU_BREAK,
              { label: 'Delete…', danger: true, onClick: () => props.onDeleteFolder(node.folder) },
            ] })
          }}
        >
          <button
            className="tree-twisty"
            aria-expanded={!isCollapsed}
            aria-label={isCollapsed ? `Expand ${node.folder.name}` : `Collapse ${node.folder.name}`}
            onClick={() => toggle(node.folder.id)}
          >
            <Chevron />
          </button>
          <span className="tree-icon tree-folder-icon" aria-hidden="true">
            <FolderIcon open={!isCollapsed} />
          </span>
          <span className="tree-name">{node.folder.name}</span>
          {node.folder.team_id && (
            <span className="tag shared-tag"
                  title="Shared with a team; managed by an administrator">
              {props.teamName(node.folder.team_id)}
            </span>
          )}
        </div>

        {!isCollapsed && (
          <ul className="tree-children">
            {node.children.map((child) => renderNode(child, depth + 1))}
            {node.sessions
              .filter((s) => matches(s, needle))
              .map((s) => renderSession(s, depth + 1))}
          </ul>
        )}
      </li>
    )
  }

  const topLevelSessions = tree.sessions.filter((s) => s.folder_id === ROOT && matches(s, needle))
  const canDropAtRoot = dragging !== null

  return (
    <div
      className={'tree' + (dropTarget === ROOT && canDropAtRoot ? ' drop-target' : '')}
      onDragOver={(e) => { if (canDropAtRoot) { e.preventDefault(); setDropTarget(ROOT) } }}
      onDrop={(e) => { e.preventDefault(); dropInto(ROOT) }}
    >
      <ul className="tree-children">
        {roots.map((node) => renderNode(node, 0))}
        {topLevelSessions.map((s) => renderSession(s, 0))}
      </ul>

      {roots.length === 0 && topLevelSessions.length === 0 && (
        <p className="muted tree-empty">
          {needle ? 'Nothing matches.' : 'No saved connections yet.'}
        </p>
      )}

      {menu && (
        <ContextMenu x={menu.x} y={menu.y} items={menu.items}
                     onClose={() => setMenu(null)} />
      )}
    </div>
  )
}

/** Pixels of indent per tree level, and the twisty's footprint (box + gap). */
const INDENT = 16
const TWISTY = 16

/**
 * Where a context menu opens. A menu raised from the keyboard (the menu key
 * or Shift+F10) carries no pointer position, so it opens under the row
 * instead of in the window's top-left corner.
 */
function menuAt(e: React.MouseEvent<HTMLElement>): { x: number; y: number } {
  if (e.clientX === 0 && e.clientY === 0) {
    const r = e.currentTarget.getBoundingClientRect()
    return { x: r.left + 24, y: r.bottom }
  }
  return { x: e.clientX, y: e.clientY }
}

/** The twisty: a small chevron that the stylesheet rotates when open. */
function Chevron() {
  return (
    <svg className="tree-chevron" width="10" height="10" viewBox="0 0 10 10"
         aria-hidden="true" focusable="false">
      <path d="M3.5 1.5 7 5l-3.5 3.5" fill="none" stroke="currentColor"
            strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** A manila folder, the way Windows has drawn one for thirty years. */
function FolderIcon({ open }: { open: boolean }) {
  const edge = '#b08a2e'
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      {open ? (
        <>
          <path d="M1.5 13.5v-10h4.2l1.5 1.5h6.3v2.5" fill="#dcb240" stroke={edge}
                strokeLinejoin="round" />
          <path d="M1.5 13.5l2.2-6h11l-2.2 6z" fill="#f0d27a" stroke={edge}
                strokeLinejoin="round" />
        </>
      ) : (
        <>
          <path d="M1.5 13.5v-10h4.2l1.5 1.5h7.3v8.5z" fill="#dcb240" stroke={edge}
                strokeLinejoin="round" />
          <path d="M1.5 6.5h13v7h-13z" fill="#e8c35a" stroke={edge}
                strokeLinejoin="round" />
        </>
      )}
    </svg>
  )
}

/** A saved connection: a small terminal window with a prompt in it. */
function SessionIcon() {
  return (
    <svg className="tree-screen" width="16" height="16" viewBox="0 0 16 16"
         aria-hidden="true" focusable="false">
      <rect className="tree-screen-glass" x="1.5" y="2.5" width="13" height="11" rx="1"
            stroke="currentColor" />
      <path d="M1.5 5h13" fill="none" stroke="currentColor" />
      <path d="M4 7.5l2 1.5-2 1.5M7.5 11h3" fill="none" stroke="currentColor"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** Every saved connection in a folder and its subfolders. */
function sessionsUnder(node: Node): SavedSession[] {
  return [...node.sessions, ...node.children.flatMap(sessionsUnder)]
}

function buildTree(tree: Tree): Node[] {
  const nodes = new Map<string, Node>()
  for (const folder of tree.folders) {
    nodes.set(folder.id, { folder, children: [], sessions: [] })
  }

  for (const session of tree.sessions) {
    nodes.get(session.folder_id)?.sessions.push(session)
  }

  const roots: Node[] = []
  for (const node of nodes.values()) {
    const parent = nodes.get(node.folder.parent_id)
    // A folder whose parent is missing is shown at the top level rather than
    // hidden: losing a device list to a data inconsistency is far worse than
    // showing it in the wrong place.
    if (parent && parent !== node) parent.children.push(node)
    else roots.push(node)
  }

  const byOrder = (a: { folder: Folder }, b: { folder: Folder }) =>
    a.folder.sort_order - b.folder.sort_order || a.folder.name.localeCompare(b.folder.name)
  const sortSessions = (list: SavedSession[]) =>
    list.sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name))

  const sortDeep = (list: Node[]) => {
    list.sort(byOrder)
    for (const node of list) {
      sortSessions(node.sessions)
      sortDeep(node.children)
    }
  }
  sortDeep(roots)

  return roots
}

function matches(session: SavedSession, needle: string): boolean {
  if (!needle) return true
  return (
    session.name.toLowerCase().includes(needle) ||
    session.hostname.toLowerCase().includes(needle) ||
    session.username.toLowerCase().includes(needle)
  )
}

/** filterNode reports whether a folder or anything beneath it matches. */
function filterNode(node: Node, needle: string): boolean {
  if (!needle) return true
  if (node.folder.name.toLowerCase().includes(needle)) return true
  if (node.sessions.some((s) => matches(s, needle))) return true
  return node.children.some((child) => filterNode(child, needle))
}
