import { useCallback, useEffect, useState } from 'react'
import { downloadURL, uploadFile, type FileEntry } from '../api'
import { formatBytes } from './FilePane'

export interface FileEditorProps {
  sessionId: string
  entry: FileEntry
  onClose: () => void
  onSaved: () => void
}

/**
 * MaxEditableBytes bounds what the editor will open.
 *
 * An editor is for a configuration file, a script, a set of interface
 * definitions — things measured in kilobytes. Loading a multi-gigabyte log
 * into a textarea would freeze the tab, so past this the file is offered as a
 * download instead, which is what the user wanted anyway.
 */
export const MaxEditableBytes = 2 * 1024 * 1024

/**
 * FileEditor edits a remote file in place.
 *
 * The round trip is deliberately the same one a transfer uses — download the
 * bytes, upload them back — rather than a special editing endpoint. That
 * keeps one code path for writing to a host, so there is one place where
 * permissions, resumption and auditing have to be right.
 */
export function FileEditor(props: FileEditorProps) {
  const [text, setText] = useState('')
  const [original, setOriginal] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [binary, setBinary] = useState(false)

  const tooLarge = props.entry.size > MaxEditableBytes

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(downloadURL(props.sessionId, props.entry.path), {
        credentials: 'same-origin',
      })
      if (!response.ok) {
        throw new Error(`The file could not be read (${response.status}).`)
      }

      const buffer = await response.arrayBuffer()
      const bytes = new Uint8Array(buffer)

      // A NUL byte in the first few kilobytes is the same heuristic grep and
      // git use, and for the same reason: editing a binary as text silently
      // corrupts it on save.
      if (bytes.subarray(0, 8000).includes(0)) {
        setBinary(true)
        return
      }

      const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
      setText(decoded)
      setOriginal(decoded)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [props.sessionId, props.entry.path])

  useEffect(() => {
    if (tooLarge) {
      setLoading(false)
      return
    }
    void load()
  }, [load, tooLarge])

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      const encoded = new TextEncoder().encode(text)
      await uploadFile(props.sessionId, props.entry.path, new Blob([encoded]))
      setOriginal(text)
      props.onSaved()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  const dirty = text !== original

  const close = () => {
    if (dirty && !window.confirm('Close without saving? The changes will be lost.')) return
    props.onClose()
  }

  return (
    <div className="editor-overlay" role="dialog" aria-label={`Editing ${props.entry.name}`}>
      <div className="card editor-card">
        <div className="spread">
          <div>
            <h2>{props.entry.name}</h2>
            <p className="muted mono">{props.entry.path}</p>
          </div>
          <div className="row">
            {!tooLarge && !binary && (
              <button className="primary" onClick={() => void save()} disabled={saving || !dirty}>
                {saving ? 'Saving…' : dirty ? 'Save' : 'Saved'}
              </button>
            )}
            <button onClick={close}>Close</button>
          </div>
        </div>

        {error && <div className="error">{error}</div>}

        {tooLarge && (
          <>
            <p>
              This file is {formatBytes(props.entry.size)}, which is more than the
              editor will open. Download it instead.
            </p>
            <a className="link"
               href={downloadURL(props.sessionId, props.entry.path)}
               download={props.entry.name}>Download {props.entry.name}</a>
          </>
        )}

        {binary && (
          <>
            <p>
              This looks like a binary file. Editing it as text would corrupt it,
              so the editor will not open it.
            </p>
            <a className="link"
               href={downloadURL(props.sessionId, props.entry.path)}
               download={props.entry.name}>Download {props.entry.name}</a>
          </>
        )}

        {loading && <p className="muted">Loading…</p>}

        {!loading && !tooLarge && !binary && (
          <>
            <textarea
              className="editor-text"
              aria-label={`Contents of ${props.entry.name}`}
              spellCheck={false}
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
            <p className="muted">
              {dirty ? 'Unsaved changes.' : 'No changes.'} Saving replaces the file
              on the host; its permissions and owner are left alone.
            </p>
          </>
        )}
      </div>
    </div>
  )
}
