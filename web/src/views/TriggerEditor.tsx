import { MAX_TRIGGERS, type Trigger, type TriggerAction } from '../api'
import { COLOUR_NAMES } from '../terminal/highlight'

/**
 * TriggerEditor edits the rules that watch a session's output.
 *
 * Shared by the connection form and the folder form, because the interesting
 * case is the folder one: "tell me when any of these three hundred switches
 * logs a link flap" is one rule in one place, and a rule per connection is
 * three hundred rules nobody maintains.
 */
export interface TriggerEditorProps {
  triggers: Trigger[]
  onChange: (triggers: Trigger[]) => void
  /** Folder defaults apply to every connection inside, so the note differs. */
  scope: 'connection' | 'folder'
}

const ACTIONS: { value: TriggerAction; label: string; note: string }[] = [
  {
    value: 'notify', label: 'Tell me',
    note: 'A notice in the terminal. The only action that cannot go wrong.',
  },
  {
    value: 'highlight', label: 'Highlight it',
    note: 'Colours the matching text and marks it in the scrollbar.',
  },
  {
    value: 'send', label: 'Type something',
    note: 'Types at the device, whether or not anybody is watching.',
  },
  {
    value: 'stop', label: 'End the session',
    note: 'For a match that means continuing would make things worse.',
  },
]

export function TriggerEditor({ triggers, onChange, scope }: TriggerEditorProps) {
  const set = (index: number, patch: Partial<Trigger>) => {
    onChange(triggers.map((t, i) => (i === index ? { ...t, ...patch } : t)))
  }

  const add = () => {
    onChange([...triggers, { name: '', pattern: '', action: 'notify' }])
  }

  return (
    <details className="triggers">
      <summary>
        Watch rules {triggers.length > 0 && <span className="tag">{triggers.length}</span>}
      </summary>

      <p className="muted">
        Each rule watches the output for a regular expression and does one
        thing when it matches. They run on the server, so a rule that answers
        a <code>[confirm]</code> prompt during a twenty-minute upgrade works
        with the browser closed.
        {scope === 'folder' && ' Rules set here apply to every connection in this folder.'}
      </p>

      {triggers.map((trigger, index) => (
        <fieldset key={index} className="trigger">
          <div className="row">
            <label className="grow">
              Name
              <input
                value={trigger.name}
                placeholder="link went down"
                onChange={(e) => set(index, { name: e.target.value })}
              />
            </label>
            <label className="grow">
              When the output matches
              <input
                value={trigger.pattern}
                placeholder="(?i)line protocol.*down"
                onChange={(e) => set(index, { pattern: e.target.value })}
              />
            </label>
          </div>

          <div className="row">
            <label className="grow">
              Then
              <select
                value={trigger.action}
                onChange={(e) => set(index, { action: e.target.value as TriggerAction })}
              >
                {ACTIONS.map((a) => (
                  <option key={a.value} value={a.value}>{a.label}</option>
                ))}
              </select>
            </label>

            {trigger.action === 'highlight' && (
              <label className="grow">
                Colour
                <select
                  value={trigger.colour ?? 'amber'}
                  onChange={(e) => set(index, { colour: e.target.value })}
                >
                  {COLOUR_NAMES.map((name) => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              </label>
            )}

            {trigger.action === 'send' && (
              <label className="grow">
                Type
                <input
                  value={trigger.send ?? ''}
                  placeholder="%PASSWORD%\r"
                  onChange={(e) => set(index, { send: e.target.value })}
                />
              </label>
            )}

            <label>
              At most
              <input
                type="number" min={0} max={1000}
                value={trigger.max_fires ?? 0}
                onChange={(e) => set(index, { max_fires: Number(e.target.value) })}
              />
            </label>
          </div>

          <p className="muted">
            {ACTIONS.find((a) => a.value === trigger.action)?.note}
            {trigger.action === 'send' && (
              <>
                {' '}Use <code>%PASSWORD%</code> rather than typing a password
                here: it is filled in from the credential at connect time, and
                a literal one would be stored unencrypted. Capture groups from
                the pattern are available as <code>$1</code>, <code>$2</code>.
              </>
            )}
            {' '}A limit of 0 uses the default of 25 — which is what stops a
            rule whose own output matches its own pattern from running forever.
          </p>

          <div className="row">
            <label className="inline">
              <input
                type="checkbox"
                checked={Boolean(trigger.disabled)}
                onChange={(e) => set(index, { disabled: e.target.checked })}
              />
              Keep but do not run
            </label>
            <button
              type="button"
              onClick={() => onChange(triggers.filter((_, i) => i !== index))}
            >
              Remove
            </button>
          </div>
        </fieldset>
      ))}

      {triggers.length < MAX_TRIGGERS ? (
        <button type="button" onClick={add}>Add a rule</button>
      ) : (
        <p className="muted">
          {MAX_TRIGGERS} rules is the limit. Every rule is matched against every
          line of output, so this is a bound on work per byte as much as on
          configuration.
        </p>
      )}
    </details>
  )
}
