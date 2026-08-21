import { useEffect, useState } from 'react'

/**
 * TranscriptViewer shows a recording in the browser, which is the difference
 * between "full audit" and a folder of .log files: the reviewer reads the
 * session where they found it, without a download step.
 *
 * Terminal escape sequences are stripped for reading — colour codes and
 * cursor movement are how the session looked, not what it said, and a
 * transcript viewer's job is what it said.
 */
export function TranscriptViewer({ url, title, onClose }: {
  /** The transcript's download URL; ?view=1 is appended here. */
  url: string
  title: string
  onClose: () => void
}) {
  const [text, setText] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const r = await fetch(url + (url.includes('?') ? '&' : '?') + 'view=1', {
          credentials: 'same-origin',
        })
        if (!r.ok) throw new Error(`The transcript could not be read (${r.status}).`)
        const raw = await r.text()
        if (!cancelled) setText(stripEscapes(raw))
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err))
      }
    })()
    return () => { cancelled = true }
  }, [url])

  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', key)
    return () => document.removeEventListener('keydown', key)
  }, [onClose])

  return (
    <div className="editor-overlay">
      <div className="card editor-card">
        <div className="spread">
          <h2 className="mono transcript-title">{title}</h2>
          <div className="row">
            <a className="link" href={url}>Download</a>
            <button onClick={onClose}>Close</button>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
        {text === null && !error && <p className="muted">Loading…</p>}
        {text !== null && (
          <pre className="editor-text transcript-text">{text}</pre>
        )}
      </div>
    </div>
  )
}

/**
 * stripEscapes removes ANSI escape sequences and normalises carriage returns
 * so the transcript reads as text. Progress bars drawn with bare CR collapse
 * to their final state, which is what a reader wants from them anyway.
 */
function stripEscapes(raw: string): string {
  const esc = String.fromCharCode(27)
  const bel = String.fromCharCode(7)
  const backslash = String.fromCharCode(92)
  const newline = String.fromCharCode(10)
  const carriage = String.fromCharCode(13)

  // CSI: ESC [ parameters final-byte. OSC: ESC ] ... (BEL or ESC backslash).
  const csi = new RegExp(esc + backslash + '[[0-9;?]*[ -/]*[@-~]', 'g')
  const osc = new RegExp(
    esc + backslash + '][^' + bel + esc + ']*(?:' + bel + '|' + esc + backslash + backslash + ')?',
    'g',
  )
  const twoByte = new RegExp(esc + '[@-_]', 'g')

  return raw
    .replace(csi, '')
    .replace(osc, '')
    .replace(twoByte, '')
    .split(newline)
    .map((line) => {
      const parts = line.split(carriage)
      return parts[parts.length - 1] === '' && parts.length > 1
        ? parts[parts.length - 2]!
        : parts[parts.length - 1]!
    })
    .join(newline)
}
