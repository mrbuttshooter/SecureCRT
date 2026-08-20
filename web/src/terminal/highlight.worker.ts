/// <reference lib="es2022" />

// Matching keyword-highlighting rules, off the main thread.
//
// The rules are regular expressions written by whoever saved the connection.
// On the server they are RE2, which cannot be slow — that is the whole reason
// triggers can take a pattern at all. In a browser they are JavaScript's
// backtracking engine, where `(a+)+$` against forty characters is not slow but
// effectively infinite, and a pattern that is perfectly valid RE2 can be
// exactly that.
//
// So the guarantee has to be rebuilt rather than assumed, and the only way to
// do that in a browser is to run the matching somewhere that can be killed.
// Hence a worker. The page posts lines here, and if an answer does not come
// back inside its budget the whole worker is terminated — a regular expression
// that has disappeared into a backtracking hole has no other exit, because it
// never yields.
//
// Nothing about this is a security boundary: the rules belong to the person
// reading the output, or to the folder their connection sits in. It is an
// availability one. A rule inherited from a shared folder must not be able to
// freeze a colleague's tab.

interface Rule {
  name: string
  pattern: string
  colour: string
}

interface Line {
  key: number
  text: string
}

interface Span {
  key: number
  x: number
  width: number
  colour: string
  rule: string
}

type Incoming =
  | { type: 'rules'; rules: Rule[] }
  | { type: 'scan'; batch: number; lines: Line[] }

type Outgoing =
  | { type: 'rejected'; rule: string; reason: string }
  | { type: 'scanned'; batch: number; spans: Span[] }

const ctx = self as unknown as {
  onmessage: ((event: MessageEvent<Incoming>) => void) | null
  postMessage: (message: Outgoing) => void
}

/**
 * How much of one line is matched against.
 *
 * A terminal line is at most a few hundred columns; anything longer here is a
 * line that wrapped, or a device printing a wall of text with no newline in
 * it. Truncating bounds the input to the regular expressions, which is not a
 * defence on its own — see above — but does keep the ordinary case cheap.
 */
const MAX_LINE = 1024

/** How many spans one line may produce, so a `.` rule cannot flood the page. */
const MAX_SPANS_PER_LINE = 64

let compiled: { rule: Rule; pattern: RegExp }[] = []

/**
 * Builds a JavaScript regular expression from a pattern Go accepted.
 *
 * The two dialects are close but not the same, and the gap sits exactly where
 * the common rules are. `(?i)error` — case-insensitive, the single most
 * written highlight pattern there is — is ordinary RE2 and a syntax error in
 * JavaScript, which has no inline flags. So a leading flag group is lifted
 * into the constructor's flags argument, which is what it means, and Go's
 * named-capture spelling is translated too.
 *
 * Inline flags anywhere but the start cannot be expressed in JavaScript at
 * all. Those patterns are refused by name rather than quietly never matching.
 *
 * No `u` flag: it makes JavaScript stricter about escapes than RE2 is, so
 * setting it would refuse patterns the server accepted. The cost is that
 * offsets count UTF-16 code units, which differs from terminal cells only for
 * characters outside the basic plane.
 */
function toRegExp(pattern: string): RegExp {
  let flags = 'g'

  const leading = /^\(\?([ims]+)\)/.exec(pattern)
  if (leading && leading[1]) {
    for (const flag of leading[1]) {
      if (!flags.includes(flag)) flags += flag
    }
    pattern = pattern.slice(leading[0].length)
  }

  // (?P<name>…) in Go, (?<name>…) in JavaScript. The same thing spelled
  // differently, and a pattern using it is otherwise rejected outright.
  pattern = pattern.replace(/\(\?P</g, '(?<')

  return new RegExp(pattern, flags)
}

ctx.onmessage = (event: MessageEvent<Incoming>) => {
  const message = event.data

  if (message.type === 'rules') {
    compiled = []
    for (const rule of message.rules) {
      try {
        compiled.push({ rule, pattern: toRegExp(rule.pattern) })
      } catch (err) {
        // A pattern Go accepted and JavaScript will not. Named rather than
        // dropped silently, so somebody whose colours never appear is told
        // which rule is the reason.
        ctx.postMessage({
          type: 'rejected', rule: rule.name,
          reason: err instanceof Error ? err.message : String(err),
        })
      }
    }
    return
  }

  const spans: Span[] = []
  for (const line of message.lines) {
    const text = line.text.length > MAX_LINE ? line.text.slice(0, MAX_LINE) : line.text
    let found = 0

    for (const { rule, pattern } of compiled) {
      pattern.lastIndex = 0
      let match: RegExpExecArray | null
      while ((match = pattern.exec(text)) !== null) {
        if (match[0].length > 0) {
          spans.push({
            key: line.key, x: match.index, width: match[0].length,
            colour: rule.colour, rule: rule.name,
          })
          found++
        } else {
          // A pattern that matches the empty string would otherwise never
          // advance. Nothing to draw, so step over it.
          pattern.lastIndex++
        }
        if (found >= MAX_SPANS_PER_LINE) break
      }
      if (found >= MAX_SPANS_PER_LINE) break
    }
  }

  ctx.postMessage({ type: 'scanned', batch: message.batch, spans })
}
