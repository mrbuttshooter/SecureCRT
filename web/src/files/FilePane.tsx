import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError, api, downloadURL, openFileSession,
  type FileEntry, type FileSession, type Listing, type SavedSession,
} from '../api'
import { HostKeyDialog } from '../terminal/HostKeyDialog'
import type { HostKeyInfo } from '../terminal/socket'

export interface FilePaneProps {
  /** Which side this is, used to label drags between panes. */
  side: 'left' | 'right'
  connections: SavedSession[]
  /** The saved connection this pane is browsing, if any. */
  sessionId: string
  onSessionChange: (sessionId: string) => void
  /** Called when something dropped here came from the other pane. */
  onCopyFrom: (source: { sessionId: string; path: string }, destination: string) => void
  /** Called when local files were dropped, to be uploaded here. */
  onUpload: (files: File[], sessionId: string, directory: string) => void
  /** Bumped by the parent to force a reload after a transfer finishes. */
  reloadToken: number
  onOpenEditor: (sessionId: string, entry: FileEntry) => void
  onError: (message: string) => void
}

/** The MIME type used for drags between panes. */
export const DRAG_TYPE = 'application/x-bkd-file'

/**
 * FilePane is one side of the file browser.
 *
 * Two things it deliberately does not do. It does not poll: a directory
 * listing is a round trip to a device that may be a switch with a slow
 * management plane, and refreshing one every few seconds because a browser
 * tab is open is exactly the kind of background load that gets a tool banned.
 * It reloads when something changed it, and when asked.
 *
 * And it does not sort client-side. The server already returns directories
 * first and then names case-insensitively, so re-sorting here would only
 * create a second opinion for the two to disagree about.
 */
export function FilePane(props: FilePaneProps) {
  const [session, setSession] = useState<FileSession | null>(null)
  const [listing, setListing] = useState<Listing | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [prompt, setPrompt] = useState<HostKeyInfo | null>(null)
  const [dropActive, setDropActive] = useState(false)
  const [filter, setFilter] = useState('')
  const [pathDraft, setPathDraft] = useState('')

  const uploadInput = useRef<HTMLInputElement>(null)

  const load = useCallback(async (sessionId: string, directory: string) => {
    if (!sessionId) return
    setLoading(true)
    setError(null)
    try {
      const query = new URLSearchParams({ session: sessionId })
      if (directory) query.set('path', directory)

      const result = await api.get<Listing>(`/api/files/list?${query}`)
      setListing(result)
      setPathDraft(result.path)
      setSelected(new Set())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  // Opening a connection: ask, and answer the host key question if it comes
  // back unanswered.
  const connect = useCallback(async (sessionId: string, fingerprint?: string) => {
    if (!sessionId) {
      setSession(null)
      setListing(null)
      return
    }

    setLoading(true)
    setError(null)
    try {
      const opened = await openFileSession(sessionId, fingerprint)
      setSession(opened)
      setPrompt(null)
      await load(sessionId, opened.home)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'host_key_prompt') {
        const hostKey = err.details.host_key as HostKeyInfo | undefined
        if (hostKey) {
          setPrompt(hostKey)
          setLoading(false)
          return
        }
      }
      setSession(null)
      setListing(null)
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [load])

  useEffect(() => {
    void connect(props.sessionId)
    // connect is stable; re-running on every render would reconnect endlessly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.sessionId])

  // A transfer that touched this pane invalidates what it is showing.
  useEffect(() => {
    if (props.reloadToken && session && listing) {
      void load(session.session_id, listing.path)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.reloadToken])

  const entries = useMemo(() => {
    if (!listing) return []
    const needle = filter.trim().toLowerCase()
    if (!needle) return listing.entries
    return listing.entries.filter((e) => e.name.toLowerCase().includes(needle))
  }, [listing, filter])

  const open = (entry: FileEntry) => {
    if (!session) return
    if (entry.is_dir || entry.target_is_dir) {
      void load(session.session_id, entry.path)
      return
    }
    props.onOpenEditor(session.session_id, entry)
  }

  const toggle = (entry: FileEntry, additive: boolean) => {
    setSelected((previous) => {
      const next = additive ? new Set(previous) : new Set<string>()
      if (previous.has(entry.path) && additive) next.delete(entry.path)
      else next.add(entry.path)
      return next
    })
  }

  const refresh = () => {
    if (session && listing) void load(session.session_id, listing.path)
  }

  const act = async (what: string, run: () => Promise<unknown>) => {
    try {
      await run()
      refresh()
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      setError(`${what}: ${message}`)
      props.onError(message)
    }
  }

  const makeDirectory = () => {
    if (!session || !listing) return
    const name = window.prompt('Name for the new folder')
    if (!name) return
    void act('Creating a folder', () =>
      api.post('/api/files/mkdir', {
        session: session.session_id,
        path: joinPath(listing.path, name),
      }))
  }

  const rename = (entry: FileEntry) => {
    if (!session || !listing) return
    const name = window.prompt(`Rename “${entry.name}” to`, entry.name)
    if (!name || name === entry.name) return
    void act('Renaming', () =>
      api.post('/api/files/rename', {
        session: session.session_id,
        from: entry.path,
        to: joinPath(listing.path, name),
      }))
  }

  const chmod = (entry: FileEntry) => {
    if (!session) return
    const mode = window.prompt(
      `Permissions for “${entry.name}”, in octal as chmod takes them`, entry.mode)
    if (!mode || mode === entry.mode) return
    void act('Changing permissions', () =>
      api.post('/api/files/chmod', {
        session: session.session_id, path: entry.path, mode,
      }))
  }

  const chown = (entry: FileEntry) => {
    if (!session) return
    const owner = window.prompt(
      `Owner for “${entry.name}” — a name or a numeric id, blank to leave it`,
      entry.owner || String(entry.uid))
    if (owner === null) return
    const group = window.prompt(
      `Group for “${entry.name}” — blank to leave it`,
      entry.group || String(entry.gid))
    if (group === null) return

    void act('Changing ownership', () =>
      api.post('/api/files/chown', {
        session: session.session_id, path: entry.path, owner, group,
      }))
  }

  const remove = (entry: FileEntry) => {
    if (!session) return

    const what = entry.is_dir && !entry.is_symlink
      ? `“${entry.name}” and everything inside it`
      : `“${entry.name}”`
    if (!window.confirm(`Delete ${what}? This cannot be undone.`)) return

    const query = new URLSearchParams({ session: session.session_id, path: entry.path })
    void act('Deleting', () => api.delete(`/api/files/entry?${query}`))
  }

  const onDragStart = (event: React.DragEvent, entry: FileEntry) => {
    if (!session) return
    event.dataTransfer.setData(DRAG_TYPE, JSON.stringify({
      sessionId: session.session_id,
      path: entry.path,
      name: entry.name,
    }))
    event.dataTransfer.effectAllowed = 'copy'
  }

  const onDrop = (event: React.DragEvent) => {
    event.preventDefault()
    setDropActive(false)
    if (!session || !listing) return

    // Files dragged from the desktop.
    if (event.dataTransfer.files.length > 0) {
      props.onUpload(Array.from(event.dataTransfer.files), session.session_id, listing.path)
      return
    }

    const raw = event.dataTransfer.getData(DRAG_TYPE)
    if (!raw) return

    try {
      const dragged = JSON.parse(raw) as { sessionId: string; path: string }
      // Dropping something onto the pane it came from would be a copy into
      // its own directory, which is never what the gesture meant.
      if (dragged.sessionId === session.session_id &&
          parentOf(dragged.path) === listing.path) {
        return
      }
      props.onCopyFrom(dragged, listing.path)
    } catch {
      // Not one of ours.
    }
  }

  const chooseUploads = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!session || !listing || !event.target.files) return
    props.onUpload(Array.from(event.target.files), session.session_id, listing.path)
    event.target.value = ''
  }

  return (
    <section
      className={'file-pane' + (dropActive ? ' drop-active' : '')}
      data-testid={`file-pane-${props.side}`}
      onDragOver={(e) => { e.preventDefault(); setDropActive(true) }}
      onDragLeave={() => setDropActive(false)}
      onDrop={onDrop}
    >
      <div className="file-head">
        <select
          aria-label={`Host for the ${props.side} pane`}
          value={props.sessionId}
          onChange={(e) => props.onSessionChange(e.target.value)}
        >
          <option value="">Choose a connection…</option>
          {props.connections.map((c) => (
            <option key={c.id} value={c.id}>{c.name} — {c.hostname}</option>
          ))}
        </select>

        <div className="row">
          <button onClick={() => session && listing && void load(session.session_id, listing.parent)}
                  disabled={!listing || listing.path === '/'}>Up</button>
          <button onClick={refresh} disabled={!session}>Refresh</button>
          <button onClick={makeDirectory} disabled={!session}>New folder</button>
          <button onClick={() => uploadInput.current?.click()} disabled={!session}>Upload</button>
          <input
            ref={uploadInput}
            type="file"
            multiple
            className="hidden-input"
            aria-label={`Upload to the ${props.side} pane`}
            onChange={chooseUploads}
          />
        </div>

        <form
          className="path-bar"
          onSubmit={(e) => {
            e.preventDefault()
            if (session) void load(session.session_id, pathDraft)
          }}
        >
          <input
            aria-label={`Path on the ${props.side} pane`}
            value={pathDraft}
            onChange={(e) => setPathDraft(e.target.value)}
            placeholder="/"
            disabled={!session}
          />
        </form>

        <input
          className="filter"
          aria-label={`Filter the ${props.side} pane`}
          placeholder="Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          disabled={!session}
        />
      </div>

      {error && <div className="error">{error}</div>}

      {!session && !loading && !prompt && (
        <div className="file-empty">
          <p className="muted">Choose a connection to browse its files.</p>
          <span className="drop-hint muted">
            Files dropped here upload to the connected host
          </span>
        </div>
      )}

      {loading && <p className="muted file-empty">Loading…</p>}

      {session && listing && !loading && (
        <div className="file-list" role="grid">
          <div className="file-row file-header" role="row">
            <span className="file-name">Name</span>
            <span className="file-size">Size</span>
            <span className="file-mode">Mode</span>
            <span className="file-owner">Owner</span>
            <span className="file-time">Modified</span>
            <span className="file-actions" />
          </div>

          {entries.length === 0 && (
            <p className="muted file-empty">
              {filter ? 'Nothing matches.' : 'This folder is empty.'}
            </p>
          )}

          {entries.map((entry) => (
            <div
              key={entry.path}
              role="row"
              className={'file-row' + (selected.has(entry.path) ? ' selected' : '')}
              draggable
              onDragStart={(e) => onDragStart(e, entry)}
              onClick={(e) => toggle(entry, e.ctrlKey || e.metaKey)}
              onDoubleClick={() => open(entry)}
            >
              <button
                className="file-name"
                aria-label={entry.name}
                onDoubleClick={() => open(entry)}
                onClick={(e) => { e.stopPropagation(); toggle(entry, e.ctrlKey || e.metaKey) }}
              >
                <span className="file-icon" aria-hidden="true">
                  {entry.is_symlink ? '↗' : entry.is_dir ? '▸' : '·'}
                </span>
                <span className="file-label">
                  {entry.name}
                  {entry.is_symlink && entry.link_target && (
                    <span className="muted"> → {entry.link_target}</span>
                  )}
                </span>
              </button>

              <span className="file-size">{entry.is_dir ? '' : formatBytes(entry.size)}</span>
              <span className="file-mode mono">{entry.mode_string}</span>
              <span className="file-owner">{entry.owner || entry.uid}</span>
              <span className="file-time">{formatWhen(entry.mod_time)}</span>

              <span className="file-actions" onClick={(e) => e.stopPropagation()}>
                {!entry.is_dir && (
                  <a
                    className="link"
                    href={downloadURL(session.session_id, entry.path)}
                    download={entry.name}
                  >Download</a>
                )}
                <button className="link" onClick={() => rename(entry)}>Rename</button>
                <button className="link" onClick={() => chmod(entry)}>Mode</button>
                <button className="link" onClick={() => chown(entry)}>Owner</button>
                <button className="link danger" onClick={() => remove(entry)}>Delete</button>
              </span>
            </div>
          ))}
        </div>
      )}

      {prompt && (
        <HostKeyDialog
          info={prompt}
          onAccept={() => void connect(props.sessionId, prompt.fingerprint)}
          onReject={() => { setPrompt(null); props.onSessionChange('') }}
        />
      )}
    </section>
  )
}

/** joinPath appends a name to a remote directory. Remote paths use "/". */
export function joinPath(directory: string, name: string): string {
  if (directory.endsWith('/')) return directory + name
  return `${directory}/${name}`
}

function parentOf(p: string): string {
  const cut = p.lastIndexOf('/')
  if (cut <= 0) return '/'
  return p.slice(0, cut)
}

/**
 * formatBytes renders a size the way a file manager does.
 *
 * Binary units, because that is what every tool an engineer compares this
 * against — ls -lh, df, du — uses, and a size that disagrees with ls by 2.4%
 * invites a bug report.
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`

  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

function formatWhen(iso: string): string {
  const when = new Date(iso)
  if (Number.isNaN(when.getTime())) return ''

  const sixMonths = 1000 * 60 * 60 * 24 * 182
  // Recent files show a time and old ones a year, which is what ls does and
  // for the same reason: the useful distinction changes with age.
  if (Date.now() - when.getTime() < sixMonths) {
    return when.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  }
  return when.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}
