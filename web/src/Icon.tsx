/**
 * Toolbar icons: 16px line drawings in currentColor, inline so they cost no
 * request and follow the theme. Deliberately plain — the shapes people know
 * from every Windows toolbar, not a house style.
 */
const PATHS: Record<string, string> = {
  connect: 'M5 9V5a3 3 0 0 1 6 0v4M3 9h10v5H3zM8 11v1',
  quick: 'M9 1L3 9h5l-1 6 6-8H8z',
  reconnect: 'M13 8a5 5 0 1 1-1.5-3.5M13 2v3h-3',
  disconnect: 'M3 3l10 10M13 3L3 13',
  copy: 'M5 5h8v9H5zM3 11V2h7',
  paste: 'M5 3H3v11h10V3h-2M6 2h4v2H6z',
  find: 'M7 12A5 5 0 1 0 7 2a5 5 0 0 0 0 10zM11 11l3.5 3.5',
  settings: 'M8 10.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6L13 13M3 13l1.4-1.4M11.6 4.4L13 3',
  options: 'M2 4h7M12 4h2M2 12h3M8 12h6M9 2v4M5 10v4',
  files: 'M1.5 3.5h5l1.5 1.5h6.5v8.5h-13zM5 9.5h6M9 7.5l2 2-2 2',
  command: 'M2 3h12v10H2zM4.5 6l2 2-2 2M8 10h3.5',
  single: 'M2.5 2.5h11v11h-11z',
  split: 'M2.5 2.5h11v11h-11zM8 2.5v11',
  grid: 'M2.5 2.5h11v11h-11zM8 2.5v11M2.5 8h11',
  broadcast: 'M8 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM5 5a4.2 4.2 0 0 0 0 6M11 5a4.2 4.2 0 0 1 0 6M3 3a7 7 0 0 0 0 10M13 3a7 7 0 0 1 0 10',
  sidebar: 'M2 2.5h12v11H2zM6 2.5v11',
  'new-session': 'M2.5 2.5h11v11h-11zM8 5v6M5 8h6',
  'new-folder': 'M1.5 3.5h5l1.5 1.5h6.5v8.5h-13zM8 7v4M6 9h4',
  console: 'M2 2.5h12v4H2zM2 9.5h12v4H2zM4.5 4.5h.01M4.5 11.5h.01',
  record: 'M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  snippets: 'M2 3h12v3H2zM2 10h12v3H2zM4 4.5h.01M4 11.5h.01',
  close: 'M4 4l8 8M12 4l-8 8',
  user: 'M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM2.5 14a5.5 5.5 0 0 1 11 0',
  help: 'M8 15A7 7 0 1 0 8 1a7 7 0 0 0 0 14zM6 6a2 2 0 1 1 2.5 1.9c-.4.2-.5.5-.5.9V9.5M8 12h.01',
}

export function Icon({ name, size = 16 }: { name: keyof typeof PATHS | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
         strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"
         className="icon">
      <path d={PATHS[name] ?? ''} />
    </svg>
  )
}
