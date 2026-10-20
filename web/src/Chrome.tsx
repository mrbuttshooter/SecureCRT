import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

/** One line in a drop-down menu. */
export interface MenuEntry {
  label: string
  /** Shown right-aligned, as a reminder; the binding itself lives in keys.ts. */
  shortcut?: string
  /**
   * A tick in the margin. With `radio` it marks the current choice of
   * several (a layout, a theme); without, a toggle that is on or off.
   */
  checked?: boolean
  radio?: boolean
  disabled?: boolean
  onClick?: () => void
}

/** A separator, or a small grey heading over a group. */
export const SEPARATOR: MenuEntry = { label: '-' }
export const heading = (label: string): MenuEntry => ({ label: '#' + label })

export interface MenuDef {
  label: string
  items: MenuEntry[]
}

/** "Ctrl+Shift+Q" as aria-keyshortcuts spells it: "Control+Shift+Q". */
const ariaKeys = (shortcut?: string) =>
  shortcut ? shortcut.replace(/Ctrl/g, 'Control').replace(/PgUp/g, 'PageUp').replace(/PgDn/g, 'PageDown') : undefined

/**
 * MenuBar is the File / Edit / View row every Windows program has, and the
 * thing a SecureCRT user reaches for first.
 *
 * It behaves the way hands already know: click a title to open it, move
 * across the bar and the others open, Escape or a click elsewhere closes it.
 * From the keyboard the bar is one Tab stop; Left and Right move along it,
 * Down or Enter opens a menu and puts focus on its first item, Up and Down
 * move inside, and Escape goes back to the title. Choosing an item hands
 * focus back to wherever it was before the menu opened — usually the
 * terminal — so the next keystroke goes where the person expects.
 */
export function MenuBar({ menus, start, end }: {
  menus: MenuDef[]
  start?: ReactNode
  end?: ReactNode
}) {
  const [open, setOpen] = useState<number | null>(null)
  const [roving, setRoving] = useState(0)
  const bar = useRef<HTMLDivElement>(null)
  const titles = useRef<Array<HTMLButtonElement | null>>([])
  const dropdown = useRef<HTMLDivElement>(null)
  const hovered = useRef<number | null>(null)
  const returnTo = useRef<HTMLElement | null>(null)
  const pendingFocus = useRef<'first' | 'last' | null>(null)
  const id = useId()

  const show = (i: number, focus: 'first' | 'last' | null) => {
    if (open === null) returnTo.current = document.activeElement as HTMLElement | null
    pendingFocus.current = focus
    setRoving(i)
    setOpen(i)
  }

  const hide = (restore: 'title' | 'previous' | 'none') => {
    const was = open
    setOpen(null)
    if (restore === 'title' && was !== null) titles.current[was]?.focus()
    if (restore === 'previous') returnTo.current?.focus()
    returnTo.current = null
  }

  // Focus the first or last item once the menu has rendered.
  useLayoutEffect(() => {
    if (open === null || !pendingFocus.current) return
    const items = enabledItems()
    const target = pendingFocus.current === 'first' ? items[0] : items.at(-1)
    pendingFocus.current = null
    target?.focus()
  }, [open])

  // A click anywhere else closes the menu, leaving focus where it lands.
  useEffect(() => {
    if (open === null) return
    const away = (event: MouseEvent) => {
      if (!bar.current?.contains(event.target as Node)) {
        setOpen(null)
        returnTo.current = null
      }
    }
    document.addEventListener('mousedown', away, true)
    return () => document.removeEventListener('mousedown', away, true)
  }, [open])

  const enabledItems = () =>
    Array.from(dropdown.current?.querySelectorAll<HTMLButtonElement>('.menu-entry:not(:disabled)') ?? [])

  const moveTitle = (from: number, by: number, openIt: boolean) => {
    const next = (from + by + menus.length) % menus.length
    setRoving(next)
    titles.current[next]?.focus()
    if (openIt) show(next, 'first')
  }

  const onTitleKey = (i: number, event: React.KeyboardEvent) => {
    switch (event.key) {
      // Already open (a mouse click opened it): just step inside.
      case 'ArrowDown': case 'Enter': case ' ':
        event.preventDefault()
        if (open === i) enabledItems()[0]?.focus()
        else show(i, 'first')
        break
      case 'ArrowUp':
        event.preventDefault()
        if (open === i) enabledItems().at(-1)?.focus()
        else show(i, 'last')
        break
      case 'ArrowRight':
        event.preventDefault(); moveTitle(i, 1, open !== null); break
      case 'ArrowLeft':
        event.preventDefault(); moveTitle(i, -1, open !== null); break
      case 'Home':
        event.preventDefault(); moveTitle(0, 0, false); break
      case 'End':
        event.preventDefault(); moveTitle(menus.length - 1, 0, false); break
      case 'Escape':
        if (open !== null) { event.preventDefault(); event.stopPropagation(); hide('title') }
        break
    }
  }

  const onItemKey = (event: React.KeyboardEvent) => {
    if (open === null) return
    const items = enabledItems()
    const at = items.indexOf(document.activeElement as HTMLButtonElement)
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault(); items[(at + 1) % items.length]?.focus(); break
      case 'ArrowUp':
        event.preventDefault(); items[(at - 1 + items.length) % items.length]?.focus(); break
      case 'Home':
        event.preventDefault(); items[0]?.focus(); break
      case 'End':
        event.preventDefault(); items.at(-1)?.focus(); break
      case 'ArrowRight':
        event.preventDefault(); moveTitle(open, 1, true); break
      case 'ArrowLeft':
        event.preventDefault(); moveTitle(open, -1, true); break
      case 'Escape':
        event.preventDefault(); event.stopPropagation(); hide('title'); break
      case 'Tab':
        setOpen(null); returnTo.current = null; break
    }
  }

  return (
    <div className="menubar" ref={bar}>
      {start && <span aria-hidden="true">{start}</span>}
      <div className="menubar-menus" role="menubar" aria-label="Main menu">
        {menus.map((menu, i) => (
          <div key={menu.label} className="menubar-item">
            <button
              ref={(el) => { titles.current[i] = el }}
              id={`${id}-t${i}`}
              role="menuitem"
              tabIndex={i === roving ? 0 : -1}
              aria-haspopup="menu"
              aria-expanded={open === i}
              aria-controls={open === i ? `${id}-m${i}` : undefined}
              className={'menubar-title' + (open === i ? ' open' : '')}
              onKeyDown={(e) => onTitleKey(i, e)}
              onClick={() => {
                // A menu that hovering just opened stays open on the click
                // that follows; otherwise the click would toggle it shut.
                if (hovered.current === i) { hovered.current = null; return }
                if (open === i) hide('previous')
                else show(i, null)
              }}
              onMouseEnter={() => {
                if (open !== null && open !== i) { hovered.current = i; show(i, null) }
              }}
            >
              {menu.label}
            </button>
            {open === i && (
              <div
                ref={dropdown}
                id={`${id}-m${i}`}
                className="menu-dropdown"
                role="menu"
                aria-labelledby={`${id}-t${i}`}
                onKeyDown={onItemKey}
              >
                {menu.items.map((item, j) =>
                  item.label === '-' ? (
                    <div key={j} className="menu-separator" role="separator" />
                  ) : item.label.startsWith('#') ? (
                    <div key={j} className="menu-heading" role="presentation">{item.label.slice(1)}</div>
                  ) : (
                    <button
                      key={j}
                      tabIndex={-1}
                      role={item.radio ? 'menuitemradio' : item.checked !== undefined ? 'menuitemcheckbox' : 'menuitem'}
                      aria-checked={item.checked !== undefined ? item.checked : undefined}
                      aria-keyshortcuts={ariaKeys(item.shortcut)}
                      className="menu-entry"
                      disabled={item.disabled}
                      onClick={() => {
                        // Focus goes home first, so anything the item opens
                        // (a dialog, a search box) can take it from there.
                        const back = returnTo.current
                        setOpen(null)
                        returnTo.current = null
                        back?.focus()
                        item.onClick?.()
                      }}
                    >
                      <span className="menu-check" aria-hidden="true">
                        {item.checked ? (item.radio ? '•' : '✓') : ''}
                      </span>
                      <span className="menu-label">{item.label}</span>
                      {item.shortcut && <span className="menu-shortcut" aria-hidden="true">{item.shortcut}</span>}
                    </button>
                  ),
                )}
              </div>
            )}
          </div>
        ))}
      </div>
      {end && <div className="menubar-end">{end}</div>}
    </div>
  )
}

/**
 * The open windows, innermost last. Escape and Tab belong to the top one
 * only, so a settings window opened over a session editor closes alone
 * rather than taking the unsaved edit underneath with it.
 */
const stack: number[] = []
let nextWindow = 1

const FOCUSABLE = 'input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'

/**
 * WindowDialog is a window over the main one — Credentials, Known hosts, the
 * file browser, terminal settings — the way SecureCRT opens its dialogs. The
 * sessions behind keep running and are exactly where they were afterwards.
 *
 * While it is open the main window is inert: nothing typed can reach a
 * terminal behind it, and Tab cycles inside the window. Closing it puts
 * focus back where it was, which is usually the terminal.
 */
export function WindowDialog({ title, wide, narrow, onClose, children, className }: {
  title: string
  wide?: boolean
  narrow?: boolean
  onClose: () => void
  children: ReactNode
  className?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  const titleId = useId()

  useEffect(() => {
    const me = nextWindow++
    stack.push(me)
    const previous = document.activeElement as HTMLElement | null
    const main = document.querySelector('.mainwin')
    main?.setAttribute('inert', '')

    const box = ref.current
    // An autofocus field inside has already taken focus; otherwise the
    // first control does, so typing never lands behind the window.
    if (box && !box.contains(document.activeElement)) {
      // The body's first control, not the title bar's close button.
      const body = box.querySelector<HTMLElement>('.window-body')
      ;(box.querySelector<HTMLElement>('[autofocus]') ?? body?.querySelector<HTMLElement>(FOCUSABLE)
        ?? box).focus()
    }

    const onKey = (event: KeyboardEvent) => {
      if (stack.at(-1) !== me) return
      if (event.key === 'Escape') {
        // A right-click menu inside the window closes first, on its own.
        if (document.querySelector('.context-menu')) return
        event.preventDefault()
        event.stopPropagation()
        closeRef.current()
        return
      }
      if (event.key === 'Tab' && box) {
        const items = Array.from(box.querySelectorAll<HTMLElement>(FOCUSABLE))
          .filter((el) => el.offsetParent !== null)
        if (!items.length) { event.preventDefault(); return }
        const first = items[0]!
        const last = items.at(-1)!
        if (event.shiftKey && (document.activeElement === first || !box.contains(document.activeElement))) {
          event.preventDefault(); last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault(); first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey, true)

    return () => {
      document.removeEventListener('keydown', onKey, true)
      stack.splice(stack.indexOf(me), 1)
      if (!stack.length) main?.removeAttribute('inert')
      previous?.focus?.()
    }
  }, [])

  // Portalled to the body: the main window goes inert, and a window inside
  // it would go inert with it.
  return createPortal(
    <div className="window-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div
        ref={ref}
        tabIndex={-1}
        className={'window' + (wide ? ' wide' : '') + (narrow ? ' narrow' : '') + (className ? ' ' + className : '')}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div className="window-title">
          <h2 id={titleId}>{title}</h2>
          <button className="window-close" aria-label="Close" title="Close (Esc)" onClick={onClose}>
            {'✕'}
          </button>
        </div>
        <div className="window-body">{children}</div>
      </div>
    </div>,
    document.body,
  )
}
