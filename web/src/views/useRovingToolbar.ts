import { useEffect, useRef, type RefObject } from 'react'

/**
 * useRovingToolbar gives a toolbar the keyboard model screen readers announce
 * for one: a single Tab stop, Left and Right to move between buttons, Home
 * and End to jump to either end. Disabled buttons are skipped. The button
 * last focused keeps the Tab stop, so coming back lands where you left.
 */
export function useRovingToolbar(ref: RefObject<HTMLElement>) {
  const current = useRef(0)

  // Re-run after every render: buttons enable and disable as the session in
  // front changes, and exactly one enabled button must stay reachable.
  useEffect(() => {
    const bar = ref.current
    if (!bar) return
    const all = Array.from(bar.querySelectorAll<HTMLButtonElement>('button'))
    const enabled = all.filter((b) => !b.disabled)
    if (current.current >= enabled.length) current.current = Math.max(0, enabled.length - 1)
    all.forEach((b) => { b.tabIndex = -1 })
    if (enabled[current.current]) enabled[current.current]!.tabIndex = 0
  })

  useEffect(() => {
    const bar = ref.current
    if (!bar) return
    const enabled = () => Array.from(bar.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'))
    const move = (to: number) => {
      const list = enabled()
      if (!list.length) return
      const i = (to + list.length) % list.length
      list.forEach((b, j) => { b.tabIndex = j === i ? 0 : -1 })
      current.current = i
      list[i]!.focus()
    }
    const onKey = (event: KeyboardEvent) => {
      const at = enabled().indexOf(document.activeElement as HTMLButtonElement)
      if (at < 0) return
      if (event.key === 'ArrowRight') { event.preventDefault(); move(at + 1) }
      else if (event.key === 'ArrowLeft') { event.preventDefault(); move(at - 1) }
      else if (event.key === 'Home') { event.preventDefault(); move(0) }
      else if (event.key === 'End') { event.preventDefault(); move(enabled().length - 1) }
    }
    const onFocus = (event: FocusEvent) => {
      const at = enabled().indexOf(event.target as HTMLButtonElement)
      if (at >= 0) current.current = at
    }
    bar.addEventListener('keydown', onKey)
    bar.addEventListener('focusin', onFocus)
    return () => {
      bar.removeEventListener('keydown', onKey)
      bar.removeEventListener('focusin', onFocus)
    }
  }, [ref])
}
