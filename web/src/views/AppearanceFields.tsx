import { FONT_SIZES, THEME_LABELS } from '../terminal/themes'

/**
 * AppearanceFields sets how one connection's terminal looks, or every
 * connection's in a folder: a colour scheme and a text size. Blank inherits —
 * from the folder above, and finally from each person's own settings.
 *
 * The point is the old SecureCRT habit of giving production a background
 * nobody can mistake for the lab. Set it once on the Production folder and
 * every device inside, including ones added next year, arrives red.
 *
 * It renders only the fields. The caller decides what holds them — a category
 * panel in the session options, a group box in the folder editor — because a
 * collapsible wrapper here was controlled by the values, and clearing both
 * selects folded the section shut under the person using it.
 */
export function AppearanceFields({ scheme, size, onScheme, onSize, scope }: {
  scheme: string
  size: string
  onScheme: (value: string) => void
  onSize: (value: string) => void
  scope: 'connection' | 'folder'
}) {
  return (
    <>
      <div className="row">
        <label className="grow">
          Colour scheme
          <select value={scheme} onChange={(e) => onScheme(e.target.value)}>
            <option value="">{scope === 'folder' ? 'Not set here' : 'Inherited'}</option>
            {Object.entries(THEME_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </label>
        <label>
          Text size
          <select value={size} onChange={(e) => onSize(e.target.value)}>
            <option value="">{scope === 'folder' ? 'Not set here' : 'Inherited'}</option>
            {FONT_SIZES.map((n) => <option key={n} value={String(n)}>{n}px</option>)}
          </select>
        </label>
      </div>
      <p className="muted">
        {scope === 'folder'
          ? 'Every connection in this folder, and in folders inside it, uses these unless it sets its own.'
          : 'Blank follows the folder, then your own terminal settings.'}
        {' '}A scheme set here wins over the one chosen in terminal settings,
        so production can be red for everyone who opens it.
      </p>
    </>
  )
}
