# Tunnels and jump hosts

Reaching a port on a device, and reaching a device through another one.

Both are ordinary SSH features. What is not ordinary is the client: a browser
cannot open a listening socket, and bkd is not on your laptop, so two of the
four shapes below mean something different here than they do in OpenSSH. Where
that is true this document says so rather than letting you find out.

---

## Jump hosts

A saved connection can name other saved connections to be reached through, in
order — the same thing as OpenSSH's `ProxyJump` and SecureCRT's *Firewall*.

Set them in the connection form, under **Jump hosts**. An imported tree
already has them: the OpenSSH importer reads `ProxyJump`, the SecureCRT
importer reads `Firewall Name`, and both resolve each hop to the saved
connection it names.

What matters about the implementation:

- **Every hop is a connection in its own right.** Its own username, its own
  credential, its own host key check against its own hostname. Approving a
  bastion's fingerprint records it as the bastion, not as the device behind
  it.
- **A chain is expanded recursively.** If a jump host has jump hosts of its
  own, those are followed too, up to eight hops. That is OpenSSH's behaviour
  and the reason it is worth matching: a tree imported from somewhere else
  will rely on it.
- **One bastion is shared.** Fifty connections behind a bastion take fifty
  references on *one* bastion connection, and it closes when the last of them
  does. On equipment that counts vty lines, that is the difference between
  working and not. An engineer's own shell on the bastion shares the same
  connection, which is OpenSSH `ControlMaster` behaviour without a second
  concept.
- **A failure names the hop.** "The host refused the credential" about a
  device you did not know was involved sends you to debug the wrong thing, so
  errors say which hop of how many, by name.

A chain is checked when you save it and again when you dial it: no cycles, no
self-reference, no hosts you do not own, no non-SSH hops, no more than eight.
Deleting a connection that others jump through tells you which ones.

---

## Tunnels

Four shapes. Which of them your server offers is its operator's decision; the
Tunnels screen asks the server and tells you which setting is missing rather
than offering a button that always fails.

### Device web interface — the default, and the one most teams want

Opens a switch or router's own web page in your browser, carried over the SSH
connection. No listening port, nothing installed on your machine, and it works
through a bastion like anything else.

**It is served from a separate origin, and without one configured it is not
offered at all.** That is not caution for its own sake:

- `bkd_csrf` is deliberately readable by JavaScript. It has to be — that is
  how double-submit CSRF protection works.
- The session cookie is `HttpOnly`, but `HttpOnly` does not stop it being
  *sent*. It rides every same-origin request automatically.

So a script on any proxied page — a switch whose firmware was never
trustworthy, or one somebody else reached first — would read the token, send
it with the ambient session cookie, and hold your entire API access: every
credential you can decrypt, every host you can reach. `script-src 'self'` does
not help, because the device's scripts *would be* self.

Each tunnel is therefore served at `<id>.<tunnels.domain>`, a genuinely
separate origin with no reach into bkd's cookies or DOM.

**To enable it**, an operator sets one config line and one DNS record:

```yaml
tunnels:
  domain: "tunnels.bkd.example.com"
```

```
*.tunnels.bkd.example.com.  A  <the bkd host>
```

With Caddy, on-demand TLS issues a certificate per hostname:

```
*.tunnels.bkd.example.com {
    tls { on_demand }
    reverse_proxy 127.0.0.1:8080
}
```

Responses are hardened on the way out — bkd's own cookies are stripped from
the request, and the response carries a Content-Security-Policy confining the
page to its own origin. Bodies are **not** rewritten: device interfaces are
full of absolute paths, and the subdomain is what keeps `/js/app.js` meaning
what it says. Rewriting them would mean editing attacker-influenced HTML on
every response, forever, and failing silently whenever a URL was assembled by
string concatenation.

### Port on this server — for everything that is not HTTP

`ssh -L` opens a port on *your laptop*. There is no such thing to open from a
web page, so the port is on the bkd host instead, and the honest consequence
is that **anyone who can reach that port reaches what is behind it, with no
account here at all**.

Which is why it is off by default:

```yaml
policy:
  allow_tcp_tunnels: false

tunnels:
  bind: "127.0.0.1"          # the setting that actually decides who can reach it
  port_range: "34000-34999"  # so a firewall rule can be written once
```

`tunnels.bind` is the boundary. Loopback makes the feature useless from
anywhere but the bkd host itself, which is the safe default; widening it is a
decision to make once, knowingly. Ports are drawn at random from the range so
one tunnel's port does not give away the next — but a thousand-port range is
scanned in under a second, so the randomness is not a secret and should not be
treated as one.

Use it for a database client, an RDP client, anything speaking TCP.

### SOCKS proxy — the same port, many destinations

The same listener with a SOCKS5 handshake in front, so the destination arrives
per connection and one tunnel reaches everything the far side can. Point a
browser or a client at it.

CONNECT only: no BIND, no UDP associate. Both need the proxy to accept inbound
traffic on a client's behalf, which is a second listening surface for a use
case that has no place in reaching network equipment.

Names are passed through unresolved, so the *far* side resolves them. That is
the whole point of a SOCKS tunnel into another network: names there often do
not resolve here, and resolving them locally would quietly reach the wrong
host or nothing at all.

No authentication on the listener, and that is a consequence of where it sits
rather than an omission — it binds `tunnels.bind`, and whoever can reach that
is already on the machine. A username and password here would suggest the port
is safe to expose, which it is not.

### Port on the device — `ssh -R`, and the one that points inward

The reverse of everything above. The device listens; whatever connects there
is carried back and dialled **from this server**.

This is the one shape that keeps its OpenSSH meaning exactly, and also the one
with the largest blast radius, because it reverses the direction of trust.
Every other tunnel dials outward from a connection you authenticated. This one
lets whoever reaches a port on that device reach whatever the bkd host's
network reaches — and the bkd host is not your laptop. It holds the team's
encrypted credentials, its own API, and whatever else runs beside it.

So it has a gate of its own:

```yaml
policy:
  allow_remote_forwards: false
```

and a destination guard that is **not** configurable. Refused outright:

| Refused | Why |
|---|---|
| Loopback (`127.0.0.0/8`, `::1`) | bkd's own API sits there behind the reverse proxy, and so does the database socket |
| Link-local (`169.254.0.0/16`, `fe80::/10`) | `169.254.169.254` answers cloud instance credentials to anything that asks |
| Unspecified (`0.0.0.0`, `::`) | Not a destination |
| Multicast | Not a destination |

Everything else — including RFC 1918 — is allowed, deliberately. Reaching an
internal mirror or licence server from lab equipment with no route to it is
why the feature exists; refusing private networks would leave nothing.

The guard runs against resolved addresses, on **every** connection rather than
once when the tunnel opens, and refuses a name entirely if any of its answers
is refused. A name that answers a public address now and `127.0.0.1` a moment
later is a twenty-year-old technique, and taking the first acceptable answer
would leave the choice to resolver ordering — which an attacker picks.

Leave the port blank and the device chooses one; the tunnel reports back which.
Leave the bind address blank and the device uses its own default, which for
OpenSSH is loopback unless `GatewayPorts` says otherwise.

If the device refuses, the failure says whose decision it was:
`AllowTcpForwarding` must be on, and binding anything but loopback also needs
`GatewayPorts`.

---

## Agent forwarding

`ssh -A` reaches back to the agent on your laptop. There is no channel to a
browser — but there does not need to be one, because bkd already holds the
keys. Ticking keys under **Agent forwarding** on a connection builds an
in-memory keyring from exactly those credentials and offers it to that host.

**Better than the real thing in one way.** The keyring holds the keys you
named on that connection, not everything an agent happened to be holding. A
lab switch is not also offered your production key, which with a real agent it
almost certainly would be.

**No better in the other, and this is the part that matters.** While the
connection is open, that host can use those keys to authenticate anywhere they
are accepted, and nothing distinguishes its use from yours. That is what agent
forwarding *is*; holding the keyring server-side does not change it.

Three consequences:

- **Per connection, opt-in, off by default.**
- **Never inherited from a folder.** Every other setting fills in from the
  folder above it; this one does not, and the interface refuses it on a folder
  outright rather than storing something inert. A folder default would offer
  your keys to every host inside it, including hosts a colleague adds next
  month.
- **Each hop decides for itself.** `ssh -A -J bastion host` offers the agent
  to the bastion too. Here it does not, unless the bastion's own saved
  connection says so. The bastion is the machine most worth compromising and
  the one you are least likely to be thinking about while ticking a box on a
  switch three hops behind it.

Recorded as `agent.forwarded`, naming the keys, at a severity that outlives
ordinary retention.

A host with `AllowAgentForwarding no` declines. The terminal still opens —
that is far better than refusing to connect — and a warning says so, because
otherwise the next thing you do is an authentication that fails somewhere you
cannot see.

---

## What is not built

- **X11 forwarding.** There is no X server in a browser, so there is nowhere
  for a window to appear. Building one is a larger project than everything
  above put together.
- **Tunnels surviving a restart.** A tunnel holds a live SSH connection; after
  a restart there is no connection, so a persisted row would describe
  something that is gone.
- **A laptop-side helper.** A small local binary would give true `-L`
  semantics, and would undo "nothing installed locally". If the server-side
  listener turns out not to serve, that is the next thing to consider.
