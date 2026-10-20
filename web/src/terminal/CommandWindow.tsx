import { useEffect, useRef, useState } from 'react'
import { paneHandle } from './panes'

/**
 * Commands typed this browser session, newest last. In memory only, and that
 * is deliberate: what people type into a command window includes `enable
 * secret` and `set password`, and the product already refuses to keep a
 * keystroke log on the server for exactly that reason. Writing one into
 * localStorage would be the same mistake in a less defended place.
 */
const history: string[] = []
const HISTORY_MAX = 200

/**
 * CommandWindow is SecureCRT's View > Command Window: a line under the
 * terminals where a command is composed — edited, corrected, recalled —
 * before any of it reaches the device. On a router that echoes and executes
 * keystroke by keystroke, that is the difference between fixing a typo and
 * having sent it.
 *
 * It sends through the active pane, down the same socket as typing. So if the
 * pane is broadcasting, the command goes to the whole group, fanned out and
 * checked on the server; the window itself never chooses targets.
 */
export function CommandWindow({ activeKey, label, onClose }: {
  activeKey: string | null
  label: string | null
  onClose: () => void
}) {
  const [text, setText] = useState('')
  const [, setTick] = useState(0)
  const at = useRef(history.length)
  const draft = useRef('')
  const input = useRef<HTMLTextAreaElement>(null)

  // The target's live state and broadcast reach change without this
  // component hearing about it; a slow tick keeps the label honest.
  useEffect(() => {
    const id = window.setInterval(() => setTick((n) => n + 1), 1000)
    return () => window.clearInterval(id)
  }, [])

  useEffect(() => { input.current?.focus() }, [])

  const pane = paneHandle(activeKey)
  const live = pane?.live() ?? false
  const reach = pane?.reach() ?? 1

  const send = (withEnter: boolean) => {
    if (!pane || !live) return
    const body = text.replace(/\r\n?/g, '\n')
    if (body.includes('\n')) {
      // Several lines go through the pane's paste path, so they get the
      // paste guard and the line delay like any other multi-line paste.
      // If the guard is still asking, the text stays here: cancelling the
      // confirmation must not cost the command that was being composed.
      const sent = pane.paste(withEnter && !body.endsWith('\n') ? body + '\n' : body)
      if (!sent) {
        if (body.trim() && history.at(-1) !== body) history.push(body)
        return
      }
    } else {
      pane.type(body + (withEnter ? '\r' : ''))
    }
    if (body.trim() && history.at(-1) !== body) {
      history.push(body)
      if (history.length > HISTORY_MAX) history.shift()
    }
    at.current = history.length
    draft.current = ''
    setText('')
  }

  const recall = (step: -1 | 1) => {
    if (!history.length) return
    if (at.current === history.length) draft.current = text
    const next = Math.max(0, Math.min(history.length, at.current + step))
    at.current = next
    setText(next === history.length ? draft.current : history[next]!)
  }

  return (
    <div className="command-window" data-testid="command-window">
      <div className="command-window-head">
        <span className="muted">
          {pane
            ? <>Sends to <b>{label}</b>{reach > 1 && <span className="tag warn-tag">and {reach - 1} more, broadcasting</span>}</>
            : 'No terminal is in front.'}
          {pane && !live && <span className="muted"> · not connected</span>}
        </span>
        <span className="command-window-hint muted">
          Enter sends · Shift+Enter new line · {'↑↓'} history · Ctrl+Enter without Enter
        </span>
        <button className="link" onClick={onClose} aria-label="Close the command window">{'×'}</button>
      </div>
      <div className="command-window-body">
        <textarea
          ref={input}
          aria-label="Command to send"
          className="command-window-input"
          rows={Math.min(6, Math.max(1, text.split('\n').length))}
          placeholder={live ? 'show ip interface brief' : 'Connect a terminal to send commands'}
          value={text}
          spellCheck={false}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              send(!e.ctrlKey)
            } else if (e.key === 'ArrowUp' && !text.slice(0, e.currentTarget.selectionStart).includes('\n')) {
              e.preventDefault()
              recall(-1)
            } else if (e.key === 'ArrowDown' && !text.slice(e.currentTarget.selectionEnd).includes('\n')) {
              e.preventDefault()
              recall(1)
            } else if (e.key === 'Escape') {
              e.preventDefault()
              pane?.focus()
            }
          }}
        />
        <button className="primary" disabled={!live} onClick={() => send(true)}>Send</button>
      </div>
    </div>
  )
}
