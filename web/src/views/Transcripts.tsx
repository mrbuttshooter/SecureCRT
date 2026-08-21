import { useEffect, useState } from 'react'
import { ApiError, api } from '../api'

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
              <th>Transcript</th>
              <th>Recorded</th>
              <th>Size</th>
              <th aria-label="Actions"></th>
            </tr>
          </thead>
          <tbody>
            {list.map((t) => (
              <tr key={t.name}>
                <td className="mono">{t.name}</td>
                <td>{new Date(t.modified).toLocaleString()}</td>
                <td>{formatSize(t.size)}</td>
                <td>
                  <a className="link" href={`/api/transcripts/${encodeURIComponent(t.name)}`}>
                    Download
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}
