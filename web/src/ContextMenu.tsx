import { useEffect, useRef } from 'react'

export interface MenuItem {
  label: string
  /** Rendered dimmed and unclickable, for actions that need state we lack. */
  disabled?: boolean
  danger?: boolean
  onClick: () => void
}

/** A separator between groups of related actions. */
export const MENU_BREAK = { label: '—', disabled: true, onClick: () => {} }

/**
 * ContextMenu is the right-click menu, positioned at the pointer.
 *
 * One component shared by tabs and the tree, because a product where two
 * right-click menus behave differently is a product where neither is
 * trusted. It closes on any click, on Escape, and on scroll — the three ways
 * a menu goes stale.
 *
 * Inline position style is deliberate: the coordinates are the pointer's,
 * which no stylesheet can know. The CSP allows it (style-src includes
 * 'unsafe-inline', which xterm's DOM renderer already requires).
 */
export function ContextMenu({ x, y, items, onClose }: {
  x: number
  y: number
  items: MenuItem[]
  onClose: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const away = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node)) onClose()
    }
    const key = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      // Stopped here: a menu opened by right-clicking a terminal leaves focus
      // in xterm, and an Escape that carried on would reach vim on the host.
      event.preventDefault()
      event.stopPropagation()
      onClose()
    }
    // A terminal scrolling as output arrives is not the person scrolling
    // away from the menu, so it must not close it.
    const scrolled = (event: Event) => {
      if ((event.target as Element | null)?.closest?.('.xterm')) return
      onClose()
    }
    // Capture, so a click that opens something else still closes this first.
    document.addEventListener('mousedown', away, true)
    document.addEventListener('keydown', key, true)
    document.addEventListener('scroll', scrolled, true)
    return () => {
      document.removeEventListener('mousedown', away, true)
      document.removeEventListener('keydown', key, true)
      document.removeEventListener('scroll', scrolled, true)
    }
  }, [onClose])

  // Keep the menu on screen: flip up/left when the pointer is near an edge.
  const style: React.CSSProperties = {
    left: Math.min(x, window.innerWidth - 220),
    top: Math.min(y, window.innerHeight - items.length * 30 - 16),
  }

  return (
    <div className="context-menu" role="menu" ref={ref} style={style}>
      {items.map((item, i) =>
        item.label === '—' ? (
          <div key={i} className="context-menu-break" />
        ) : (
          <button
            key={i}
            role="menuitem"
            className={'context-menu-item' + (item.danger ? ' danger' : '')}
            disabled={item.disabled}
            onClick={() => { onClose(); item.onClick() }}
          >
            {item.label}
          </button>
        ),
      )}
    </div>
  )
}
