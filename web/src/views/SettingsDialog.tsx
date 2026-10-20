import { WindowDialog } from '../Chrome'
import { DEFAULT_PREFS, type Prefs } from '../terminal/prefs'
import {
  FONT_FAMILIES, FONT_FAMILY_LABELS, FONT_SIZES, THEME_LABELS, isThemeName,
} from '../terminal/themes'

/**
 * SettingsDialog is the one place terminal preferences live — SecureCRT's
 * Global Options, cut down to what a browser terminal can honour. Changes
 * apply as they are made, to every open pane, so the dialog doubles as a
 * preview; there is no Apply button to forget.
 *
 * What a single device should look like is set on its connection or folder
 * instead, and wins over what is chosen here.
 */
export function SettingsDialog({ prefs, onChange, onClose }: {
  prefs: Prefs
  onChange: (patch: Partial<Prefs>) => void
  onClose: () => void
}) {
  return (
    <WindowDialog title="Terminal settings" onClose={onClose} className="settings">

        <fieldset>
          <legend>Appearance</legend>
          <div className="settings-grid">
            <label>
              Colour scheme
              <select value={prefs.theme} onChange={(e) => {
                if (isThemeName(e.target.value)) onChange({ theme: e.target.value })
              }}>
                {Object.entries(THEME_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </label>
            <label>
              Font
              <select value={prefs.fontFamily} onChange={(e) => onChange({ fontFamily: e.target.value })}>
                {Object.keys(FONT_FAMILIES).map((value) => (
                  <option key={value} value={value}>{FONT_FAMILY_LABELS[value] ?? value}</option>
                ))}
              </select>
            </label>
            <label>
              Text size
              <select value={String(prefs.fontSize)}
                      onChange={(e) => onChange({ fontSize: Number(e.target.value) })}>
                {FONT_SIZES.map((n) => <option key={n} value={n}>{n}px</option>)}
              </select>
            </label>
            <label>
              Cursor
              <select value={prefs.cursorStyle}
                      onChange={(e) => onChange({ cursorStyle: e.target.value as Prefs['cursorStyle'] })}>
                <option value="block">Block</option>
                <option value="bar">Bar</option>
                <option value="underline">Underline</option>
              </select>
            </label>
            <label>
              Scrollback
              <select value={String(prefs.scrollback)}
                      onChange={(e) => onChange({ scrollback: Number(e.target.value) })}>
                {[1_000, 5_000, 10_000, 20_000, 50_000, 100_000].map((n) => (
                  <option key={n} value={n}>{n.toLocaleString()} lines</option>
                ))}
              </select>
            </label>
            <label className="check">
              <input type="checkbox" checked={prefs.cursorBlink}
                     onChange={(e) => onChange({ cursorBlink: e.target.checked })} />
              Blinking cursor
            </label>
          </div>
          <p className="muted">
            A connection or folder can set its own scheme and size — production
            in red is the classic — under Appearance in its editor. Those win
            over these.
          </p>
        </fieldset>

        <fieldset>
          <legend>Mouse and clipboard</legend>
          <label className="check">
            <input type="checkbox" checked={prefs.copyOnSelect}
                   onChange={(e) => onChange({ copyOnSelect: e.target.checked })} />
            Selecting text copies it
          </label>
          <label className="check">
            <input type="checkbox" checked={prefs.rightClickPaste}
                   onChange={(e) => onChange({ rightClickPaste: e.target.checked })} />
            Right-click pastes (Shift+right-click opens the menu)
          </label>
          <label className="check">
            <input type="checkbox" checked={prefs.pasteGuard}
                   onChange={(e) => onChange({ pasteGuard: e.target.checked })} />
            Ask before pasting more than one line
          </label>
          <label className="inline settings-delay">
            Wait
            <input inputMode="numeric" value={String(prefs.lineDelayMs)}
                   onChange={(e) => onChange({
                     lineDelayMs: Math.min(5000, Number(e.target.value.replace(/\D/g, '')) || 0),
                   })} />
            ms between pasted lines
          </label>
          <p className="muted">
            For console ports and older switches that drop characters when a
            whole configuration arrives at once. Zero sends it in one go.
          </p>
        </fieldset>

        <fieldset>
          <legend>Connections</legend>
          <label className="check">
            <input type="checkbox" checked={prefs.autoReconnect}
                   onChange={(e) => onChange({ autoReconnect: e.target.checked })} />
            Reconnect automatically when a connection drops
          </label>
          <p className="muted">
            Counts down first, and never redials after you log out, after a
            refused sign-in, or when the host key has changed.
          </p>
          <label className="check">
            <input type="checkbox" checked={prefs.confirmClose}
                   onChange={(e) => onChange({ confirmClose: e.target.checked })} />
            Ask before closing a tab that is still connected
          </label>
          <label>
            Bell
            <select value={prefs.bell}
                    onChange={(e) => onChange({ bell: e.target.value as Prefs['bell'] })}>
              <option value="visual">Flash the pane</option>
              <option value="sound">Beep</option>
              <option value="none">Nothing</option>
            </select>
          </label>
        </fieldset>

        <div className="dialog-footer">
          <button onClick={() => onChange({
            ...DEFAULT_PREFS, tree: prefs.tree, layout: prefs.layout, commandWindow: prefs.commandWindow,
          })}>
            Restore defaults
          </button>
          <button className="primary" onClick={onClose}>OK</button>
        </div>
    </WindowDialog>
  )
}
