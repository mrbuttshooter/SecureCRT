import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError, api, uploadFile,
  type FileEntry, type SavedSession, type Transfer, type Tree,
} from '../api'
import { FilePane, formatBytes, joinPath } from '../files/FilePane'
import { FileEditor } from '../files/FileEditor'

/** An upload the browser is performing, tracked here rather than server-side. */
interface Upload {
  id: string
  name: string
  path: string
  sessionId: string
  loaded: number
  total: number
  state: 'running' | 'done' | 'failed'
  error?: string
  abort: AbortController
}

/**
 * How often to ask about server-side transfers while any are running.
 *
 * Only while: a poll that continues after everything has finished is a
 * request every second, per open tab, forever, for no information. When
 * nothing is running the interval is cleared and the browser goes quiet.
 */
const TRANSFER_POLL_MS = 1000

/**
 * Files is the dual-pane browser.
 *
 * Both panes are remote. A browser cannot list the local filesystem, so the
 * "local side" of a traditional SFTP client is served by dragging files in
 * from the desktop and by ordinary downloads — and what the two panes buy
 * instead is something SecureCRT cannot do at all: dragging a directory from
 * one managed host to another, which streams host to host without passing
 * through anybody's laptop.
 */
export function Files() {
  const [connections, setConnections] = useState<SavedSession[]>([])
  const [left, setLeft] = useState('')
  const [right, setRight] = useState('')
  const [transfers, setTransfers] = useState<Transfer[]>([])
  const [uploads, setUploads] = useState<Upload[]>([])
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ sessionId: string; entry: FileEntry } | null>(null)

  // Bumped to tell a pane its listing is stale. A counter rather than a
  // callback because the panes are siblings: a copy into the right-hand pane
  // has to refresh it without the left-hand pane knowing it exists.
  const [reloadLeft, setReloadLeft] = useState(0)
  const [reloadRight, setReloadRight] = useState(0)

  const refreshPanesFor = useCallback((sessionId: string) => {
    if (sessionId === left) setReloadLeft((n) => n + 1)
    if (sessionId === right) setReloadRight((n) => n + 1)
  }, [left, right])

  useEffect(() => {
    void api.get<Tree>('/api/tree')
      .then((tree) => setConnections(tree.sessions ?? []))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
  }, [])

  // Poll only while something is running.
  const running = transfers.some((t) => t.state === 'running')
  const previouslyRunning = useRef(false)

  useEffect(() => {
    const poll = async () => {
      try {
        const result = await api.get<{ transfers: Transfer[] }>('/api/files/transfers')
        setTransfers(result.transfers ?? [])
      } catch {
        // A transient failure only makes the list briefly stale.
      }
    }

    void poll()
    if (!running) return

    const timer = window.setInterval(() => void poll(), TRANSFER_POLL_MS)
    return () => window.clearInterval(timer)
  }, [running])

  // When the last transfer finishes, whatever it touched needs rereading.
  useEffect(() => {
    if (previouslyRunning.current && !running) {
      setReloadLeft((n) => n + 1)
      setReloadRight((n) => n + 1)
    }
    previouslyRunning.current = running
  }, [running])

  const startCopy = async (
    source: { sessionId: string; path: string },
    destSession: string,
    destDirectory: string,
  ) => {
    try {
      await api.post('/api/files/copy', {
        source_session: source.sessionId,
        source_path: source.path,
        dest_session: destSession,
        dest_directory: destDirectory,
      })
      setTransfers(await api.get<{ transfers: Transfer[] }>('/api/files/transfers')
        .then((r) => r.transfers ?? []))
    } catch (err) {
      // A refusal to overwrite is the common one, and worth offering to
      // resolve rather than merely reporting.
      if (err instanceof ApiError && err.code === 'conflict') {
        if (!window.confirm('Something is already there. Overwrite it?')) return
        try {
          await api.post('/api/files/copy', {
            source_session: source.sessionId,
            source_path: source.path,
            dest_session: destSession,
            dest_directory: destDirectory,
            overwrite: true,
          })
          return
        } catch (retryErr) {
          setError(retryErr instanceof Error ? retryErr.message : String(retryErr))
          return
        }
      }
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const startUploads = (chosen: File[], sessionId: string, directory: string) => {
    for (const file of chosen) {
      const upload: Upload = {
        id: `${Date.now()}-${file.name}-${Math.round(file.size)}`,
        name: file.name,
        path: joinPath(directory, file.name),
        sessionId,
        loaded: 0,
        total: file.size,
        state: 'running',
        abort: new AbortController(),
      }
      setUploads((previous) => [...previous, upload])

      void uploadFile(sessionId, upload.path, file, {
        signal: upload.abort.signal,
        onProgress: ({ loaded, total }) =>
          setUploads((previous) => previous.map((u) =>
            u.id === upload.id ? { ...u, loaded, total } : u)),
      })
        .then(() => {
          setUploads((previous) => previous.map((u) =>
            u.id === upload.id ? { ...u, state: 'done', loaded: u.total } : u))
          refreshPanesFor(sessionId)
        })
        .catch((err: unknown) => {
          setUploads((previous) => previous.map((u) =>
            u.id === upload.id
              ? { ...u, state: 'failed', error: err instanceof Error ? err.message : String(err) }
              : u))
        })
    }
  }

  const cancelTransfer = async (id: string) => {
    try {
      await api.delete(`/api/files/transfers/${id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const paneProps = (side: 'left' | 'right') => ({
    side,
    connections,
    sessionId: side === 'left' ? left : right,
    onSessionChange: side === 'left' ? setLeft : setRight,
    reloadToken: side === 'left' ? reloadLeft : reloadRight,
    onOpenEditor: (sessionId: string, entry: FileEntry) => setEditing({ sessionId, entry }),
    onUpload: startUploads,
    onError: setError,
    onCopyFrom: (source: { sessionId: string; path: string }, destination: string) =>
      void startCopy(source, side === 'left' ? left : right, destination),
  })

  const active = [
    ...uploads.filter((u) => u.state === 'running'),
    ...transfers.filter((t) => t.state === 'running'),
  ]
  const finished = [
    ...uploads.filter((u) => u.state !== 'running'),
    ...transfers.filter((t) => t.state !== 'running'),
  ]

  return (
    <section className="files">
      {error && (
        <div className="error">
          {error} <button className="link" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      <p className="muted files-hint">
        Drag files onto a pane to upload, or between panes to copy host to
        host directly.
      </p>

      <div className="file-panes">
        <FilePane {...paneProps('left')} />
        <FilePane {...paneProps('right')} />
      </div>

      {(active.length > 0 || finished.length > 0) && (
        <div className="transfers">
          <h3>Transfers</h3>
          <ul className="plain">
            {uploads.map((upload) => (
              <li key={upload.id} className="transfer">
                <span className="transfer-name">
                  {upload.name} <span className="muted">uploading</span>
                </span>
                <progress
                  value={upload.loaded}
                  max={upload.total || 1}
                  aria-label={`Uploading ${upload.name}`}
                />
                <span className="transfer-state">
                  {upload.state === 'failed'
                    ? <span className="danger">{upload.error}</span>
                    : `${formatBytes(upload.loaded)} of ${formatBytes(upload.total)}`}
                </span>
                {upload.state === 'running' && (
                  <button className="link" onClick={() => upload.abort.abort()}>Cancel</button>
                )}
              </li>
            ))}

            {transfers.map((transfer) => (
              <li key={transfer.id} className="transfer">
                <span className="transfer-name">
                  {transfer.name}{' '}
                  <span className="muted">
                    {transfer.kind === 'copy' ? 'copying' : 'deleting'}
                  </span>
                </span>
                <progress
                  value={transfer.done_bytes}
                  max={transfer.total_bytes || 1}
                  aria-label={`${transfer.kind} ${transfer.name}`}
                />
                <span className="transfer-state">
                  {transfer.state === 'failed' && <span className="danger">{transfer.error}</span>}
                  {transfer.state === 'running' && transfer.total_files > 1 &&
                    `${transfer.done_files} of ${transfer.total_files} files`}
                  {transfer.state === 'running' && transfer.total_files <= 1 &&
                    `${formatBytes(transfer.done_bytes)} of ${formatBytes(transfer.total_bytes)}`}
                  {transfer.state === 'done' && 'Done'}
                  {transfer.state === 'cancelled' && 'Cancelled'}
                </span>
                {transfer.state === 'running' && (
                  <button className="link" onClick={() => void cancelTransfer(transfer.id)}>
                    Cancel
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {editing && (
        <FileEditor
          sessionId={editing.sessionId}
          entry={editing.entry}
          onClose={() => setEditing(null)}
          onSaved={() => refreshPanesFor(editing.sessionId)}
        />
      )}
    </section>
  )
}
