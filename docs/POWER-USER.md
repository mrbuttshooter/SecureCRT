# Snippets, watch rules, broadcast, highlighting and transcripts

The features that make a terminal something other than a window with a shell
in it. All five belong to one person's saved connections and one person's
account; none of them needs an administrator.

---

## Snippets

A snippet is a command you have typed a hundred times. The version everybody
already has is a text file beside the terminal, and half of what is in that
file is a password.

So the placeholder syntax exists to make the other choice easy:

```
interface {{port}}
 description {{note}}
 switchport access vlan {{vlan}}
```

Sending it asks for `port`, `note` and `vlan`, fills them in, and types the
result. **The values are never stored** — not in the snippet, not on the
server, not in the audit record. What is recorded is that a named snippet was
sent and to how many terminals.

The body is sent exactly as written, newlines and all, so a line that should
be entered needs a newline after it.

With a broadcast group active, a snippet goes to every terminal in the group
in one request. The server checks each one belongs to you before anything is
typed, and refuses the whole send if any of them has gone: half a rack having
received a configuration command is worse than none of it.

Limits: 16 KiB a snippet, 12 placeholders. Names are unique per person.

Snippets are personal for now. The table already carries the column that makes
them shareable with a team, so that is a permissions question for Phase 8
rather than a migration.

---

## Watch rules

A rule watches the output for a regular expression and does one of four
things.

| Action | What it does | Runs on |
|---|---|---|
| Tell me | A notice on the terminal. The only action that cannot go wrong. | the server |
| Highlight it | Colours the matching text and marks it in the scrollbar. | the browser |
| Type something | Types at the device. | the server |
| End the session | Closes it, for a match meaning things are getting worse. | the server |

The three server-side actions run **whether or not a browser is attached**,
which is the point: a rule that answers a `[confirm]` prompt during a
twenty-minute upgrade is most needed precisely when nobody is watching.

Rules are inherited from the folder, like the logon sequence — "tell me when
any of these three hundred switches logs a link flap" is one rule in one
place. A connection can override them, and an explicitly empty list is how one
connection opts out of its folder's rules.

### Patterns

Patterns are Go's `regexp`, which is RE2: linear time, no backtracking, so
there is no pattern anybody can write, by accident or on purpose, that turns a
busy console into a hung process. That is the whole reason this feature can
take a regular expression from a user at all.

Capture groups are available in what a rule types, as `$1`, `$2` and so on,
along with `%USERNAME%` and `%PASSWORD%` and the escapes `\r`, `\n`, `\t`:

```
when      Enable password for (\w+)
type      %PASSWORD%\r
```

**Never type a literal password into a rule.** `%PASSWORD%` is substituted
from the credential at connect time; a literal one is stored in the settings
document unencrypted.

### Matching against the line so far

Each rule is matched against the line as it stands, every time more of it
arrives, and a rule that has fired on the current line does not fire again
until the line ends.

That is deliberate and it is what makes prompts work: the single most common
rule anybody writes waits for a prompt, and a prompt has no newline after it.
A rule waiting for a completed line waits forever.

The consequence to be honest about: an unanchored pattern can match a prefix
that the rest of the line would have changed — `^Error` fires on a line that
turns out to say `Errors: 0`. What is lost is only the ability to write a
pattern that depends on the line being over. `$` still works once it is.

### Limits, and why they are there

- **16 rules a connection.** Every rule is matched against every line of
  output, so this bounds work per byte as much as configuration.
- **25 firings a session** by default, adjustable to 1000. This is
  load-bearing twice over: a rule whose typing produces output matching its
  own pattern is an infinite loop, and a device printing `assword:` in a loop
  must not be handed the credential ten thousand times.
- **8 KiB of unterminated line.** A device redrawing a progress bar with
  carriage returns prints indefinitely without a newline; beyond the bound the
  buffer is reset.

### What is audited

A rule that typed or a rule that ended a session, with the rule's name and the
line that matched. **Never what it typed** — that may be a password. Notices
and highlights are not recorded: they changed nothing at the far end, and
recording them would bury the two that matter.

---

## Keyword highlighting

Highlighting is the one action the server does not perform. It has no idea
what a colour is, and the text has to be marked as it is drawn.

Every match also leaves a mark in the overview ruler down the right-hand edge,
which is what makes it worth having: a 10,000-line scrollback nobody reads
becomes a map of where the errors are.

### The one thing worth knowing

The rules are the same regular expressions as every other watch rule, but in a
browser they run under JavaScript's engine rather than RE2. That engine
backtracks, so a pattern RE2 executes in microseconds can take longer than the
age of the universe, and it cannot be interrupted because it never yields.

So the matching runs in a Web Worker with a deadline. A worker that misses it
is terminated, highlighting stops for that pane, and the terminal says so
naming the rules to look at. That is the only mechanism a browser offers which
actually bounds this; a timer checked afterwards would be checked after the
tab had already frozen.

Two dialect differences are translated rather than left to fail:

- `(?i)error` — RE2's inline flags, and a syntax error in JavaScript — has its
  leading flag group lifted into the constructor. Inline flags anywhere but
  the start cannot be expressed at all, and such a rule is refused by name
  rather than quietly never matching.
- `(?P<name>…)` becomes `(?<name>…)`.

Colours are a palette — red, orange, amber, yellow, green, teal, cyan, blue,
purple, magenta, grey — or a `#rrggbb` value. The palette sets an explicit
foreground so a highlight reads the same against every terminal theme.

Only completed lines are highlighted, so a prompt is not coloured while it is
still being typed at.

---

## Broadcast

One keyboard, several terminals. Upgrading a stack is eight switches, the same
four commands, and no appetite for typing them eight times and getting the
seventh wrong.

**The fan-out happens on the server.** The browser sends its keystroke once
and the server mirrors it. Doing it the other way — the browser writing to
eight sockets — would put "may this person type into that terminal" in the
client, which is not a check at all, and would make "which terminals is this
keyboard reaching" a fact only the browser knew.

What follows from that:

- Every target is re-checked against your account at every group change. A
  stale or guessed identifier reaches nothing.
- The group is all-or-nothing. If any target has gone, the whole request is
  refused rather than silently smaller than you believe. Somebody who thinks
  they are typing at forty devices and is typing at thirty-nine has a problem
  they will not discover until it matters.
- A terminal that ends mid-session drops out of the group and says so, rather
  than failing the keystroke — one dead switch must not stop you typing at the
  other thirty-nine.
- The group belongs to **one browser tab** and lasts as long as its socket. A
  second tab on the same terminal does not inherit it, and closing the tab
  ends it. A broadcast that outlived the window it was set up in is how
  somebody reloads a page and types `reload` into forty switches.

The pane shows how many terminals its keyboard reaches while a group is
active. Starting and stopping are audited, with the count and the names —
never per keystroke, which would be a keystroke log and would bury the event
worth finding.

---

## Session transcripts

A transcript is written on the server, under `paths.session_log_dir`, one file
per session, readable only by the service account.

**A transcript records what the device printed and never what you typed.**
That is the whole shape of the decision. A keystroke log captures passwords
typed at prompts this server never sees — an enable password, a `sudo`
password, a credential for a system three hops away — and would turn every
transcript into a secret store. Output is what an incident review actually
wants: what the device said, and what it did about it.

Recording is switched on per connection, or on a folder for everything inside
it. An operator can require it for everything with `policy.record_all_sessions`,
and then it is not the user's decision — so it is said on the terminal itself
rather than left in a settings page they never open. Either way the terminal
says a session is being recorded.

Files are capped at 64 MiB; beyond that the transcript stops and the session
continues. There is no rotation and no expiry: what to keep and for how long is
a policy question, so it is left to whatever already manages the directory.

---

## Scrollback search

Already there since Phase 2 — the **Search** button on any pane. Searches the
whole scrollback, not the visible screen, and Enter or Shift-Enter steps
through matches.

---

## What was deliberately not built

- **A sandboxed JavaScript runtime for triggers.** The original scope called
  for one. A JavaScript engine evaluating per-user scripts against device
  output, inside the process holding every engineer's encrypted credentials,
  is a large surface to get right: an interpreter to keep patched, an
  interrupt mechanism for scripts that never return, a memory bound, and a
  careful account of exactly which host functions are reachable. What it buys
  over the declarative form is conditional logic and string manipulation —
  real, and wanted by a small fraction of the cases. What people configure is
  "when you see X, send Y", "when you see X, tell me", and "when you see X,
  stop".
- **Team-shared snippets.** The schema is ready; the permissions model is
  Phase 8's, and building half of it here would mean building it twice.
- **Highlighting a prompt as it is typed.** Only completed lines are matched.
