/**
 * The mark: two pylons and a span lifted mid-way — a drawbridge, drawn with
 * strokes so it stays crisp at 20px and inherits the accent colour from CSS.
 * Inline SVG rather than an asset, so it costs no request and no CSP thought.
 */
export function Brand({ size = 20 }: { size?: number }) {
  return (
    <span className="brand">
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
           stroke="currentColor" strokeWidth="2" strokeLinecap="round"
           aria-hidden="true">
        {/* pylons */}
        <path d="M4 21V9" />
        <path d="M20 21V9" />
        {/* the raised halves of the span */}
        <path d="M4 15l6-4" />
        <path d="M20 15l-6-4" />
        {/* deck */}
        <path d="M2 21h20" />
      </svg>
      <span className="brand-name"><b>bridge</b>keeper</span>
    </span>
  )
}
