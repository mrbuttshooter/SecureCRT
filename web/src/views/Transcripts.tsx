import { useEffect, useState } from 'react'
import { ApiError, api } from '../api'
import { TranscriptViewer } from './TranscriptViewer'

interface TranscriptInfo {
  name: string
  size: number
  modified: string
}

/**
 * Transcripts answers "what did I do on that switch last Tuesday".
 *
 * The list is the user's own recordings, newest first; each downloads as
 * plain text through the same-origin API, so the browser's own save dialog
 * does the rest. Recording is started from the terminal pane or by the
 * connection's "keep a transcript" setting — this page is where the results
 * live.
 */
export function Transcripts() {
  const [list, setList] = useState<TranscriptInfo[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [viewing, setViewing] = useState<TranscriptInfo | null>(null)

  useEffect(() => {
    void api
      .get<{ transcripts: TranscriptInfo[] | null }>('/api/transcripts')
      .then((r) => setList(r.transcripts ?? []))
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : String(err))
        setList([])
      })
  }, [])

  return (
    <section>
      <div className="spread">
        <h2>Transcripts</h2>
      </div>

      {error && <div className="error">{error}</div>}

      {list === null && <p className="muted">Loading…</p>}

      {list?.length === 0 && !error && (
        <div className="card">
          <p>No transcripts yet.</p>
          <p className="muted">
            Press <strong>Record</strong> on an open terminal to start one, or
            turn on “keep a transcript” in a connection’s settings to record
            every session automatically. Output only is recorded — keystrokes,
            and so passwords, are not.
          </p>
        </div>
      )}

      {list && list.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Session</th>
              <th>Recorded</th>
              <th>Size</th>
              <th aria-label="Actions"></th>
            </tr>
          </thead>
          <tbody>
            {list.map((t) => (
              <tr key={t.name}>
                <td className="mono">{sessionFrom(t.name)}</td>
                <td className="nowrap">{isoTime(t.modified)}</td>
                <td className="nowrap">{formatSize(t.size)}</td>
                <td className="nowrap">
                  <button className="link" onClick={() => setViewing(t)}>View</button>
                  {' '}
                  <a className="link" href={`/api/transcripts/${encodeURIComponent(t.name)}`}>
                    Download
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {viewing && (
        <TranscriptViewer
          url={`/api/transcripts/${encodeURIComponent(viewing.name)}`}
          title={sessionFrom(viewing.name)}
          onClose={() => setViewing(null)}
        />
      )}
    </section>
  )
}

/** The connection name buried in a transcript filename, for humans. */
function sessionFrom(name: string): string {
  return name.replace(/^[0-9]{8}-[0-9]{6}-/, '').replace(/[.]log$/, '')
}

function isoTime(v: string): string {
  const d = new Date(v)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}
