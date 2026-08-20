import { useMemo, useState } from 'react'
import type { Folder, SavedSession, Tree } from '../api'

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

  const renderSession = (s: SavedSession, depth: number) => (
    <li
      key={s.id}
      className={
        'tree-row tree-session' +
        (props.selectedId === s.id ? ' selected' : '') +
        (props.liveSessionIds.has(s.id) ? ' live' : '')
      }
      style={{ paddingLeft: `${depth * 14 + 22}px` }}
      draggable
      onDragStart={() => setDragging({ kind: 'session', id: s.id })}
      onDragEnd={() => { setDragging(null); setDropTarget(null) }}
    >
      <button
        className="tree-label"
        // The row shows a status glyph and the hostname alongside the name,
        // which would otherwise all end up in the accessible name and make
        // every row read as a sentence. The name is what identifies it.
        aria-label={s.name}
        onClick={() => props.onSelect(s)}
        onDoubleClick={() => props.onOpen(s)}
        title={`${s.username ? s.username + '@' : ''}${s.hostname}:${s.effective_port}`}
      >
        <span className="tree-icon" aria-hidden="true">
          {props.liveSessionIds.has(s.id) ? '●' : '○'}
        </span>
        <span className="tree-name">{s.name}</span>
        <span className="tree-host muted">{s.hostname}</span>
      </button>
      <button
        className="link tree-action"
        aria-label={`Connect to ${s.name}`}
        onClick={() => props.onOpen(s)}
      >
        Connect
      </button>
    </li>
  )

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
          style={{ paddingLeft: `${depth * 14 + 4}px` }}
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
        >
          <button
            className="tree-twisty"
            aria-expanded={!isCollapsed}
            aria-label={isCollapsed ? `Expand ${node.folder.name}` : `Collapse ${node.folder.name}`}
            onClick={() => toggle(node.folder.id)}
          >
            {isCollapsed ? '▸' : '▾'}
          </button>
          <span className="tree-name">{node.folder.name}</span>
          <span className="tree-tools">
            <button className="link" title="New connection here"
                    onClick={() => props.onNewSessionIn(node.folder.id)}>+ Connection</button>
            <button className="link" title="New folder here"
                    onClick={() => props.onNewFolderIn(node.folder.id)}>+ Folder</button>
            <button className="link" onClick={() => props.onEditFolder(node.folder)}>Defaults</button>
            <button className="link danger" onClick={() => props.onDeleteFolder(node.folder)}>Delete</button>
          </span>
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
    </div>
  )
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
