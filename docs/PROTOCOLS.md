# Telnet, serial lines and console servers

SSH is the protocol this is built around, and the other two exist because a
great deal of equipment still carrying production traffic cannot speak it.

---

## Telnet

**On by default**, and that is a decision rather than an oversight.

Telnet is a 1983 protocol with no authentication, no integrity and no
encryption. The password crosses the network in the clear, and so does
everything typed after it. But the devices that need it — console servers,
older switches, PDUs, anything whose management plane predates its owner's
security policy — cannot do anything else, and refusing telnet does not make
those devices go away. It makes people reach them with a tool that has no
audit log.

So the cost is made visible instead:

- The connection form warns when the protocol is telnet.
- The tab and the connection panel are marked **not encrypted**.
- Every connection is audited with `encrypted=false`, recorded at the moment
  it is made rather than inferred afterwards.

An organisation that has finished retiring its telnet estate sets
`policy.allow_telnet: false` and finds out immediately who had not noticed.

### What is negotiated

| Option | Why it matters |
|---|---|
| ECHO (RFC 857) | Who echoes typed characters. Get it wrong and every keystroke appears twice — or a password appears at all. |
| SUPPRESS-GO-AHEAD (RFC 858) | Character-at-a-time rather than line-at-a-time. Without it an interactive shell does not work. |
| TERMINAL-TYPE (RFC 1091) | What the far end thinks it is drawing to. Reported as `xterm-256color`, which is what xterm.js actually is. |
| NAWS (RFC 1073) | The window size, so full-screen tools draw correctly and follow a browser resize. |
| BINARY (RFC 856) | Both directions, which is what makes UTF-8 work. Without it the protocol is 7-bit and every accented character arrives mangled. |

Everything else is refused out loud — `DONT` to a `WILL`, `WONT` to a `DO`.
An option nobody implements still has to be answered, or a peer waiting for
the reply simply hangs and the connection appears to open and then do nothing.

Negotiation follows RFC 1143's state machine rather than answering every offer
reflexively. Two implementations that each answer every agreement read each
other's agreements as fresh offers and exchange a hundred thousand packets a
second; old telnet stacks renegotiate at moments that surprise people, so this
is not hypothetical.

### Echo, and why passwords are hidden

By default the far end is assumed to echo, because every interactive device
does. Only a peer that explicitly sends `WONT ECHO` gets local echo here.

That is also how a telnet password prompt works: the server sends `WILL ECHO`
to stop the client echoing, then does not echo the password itself. Following
negotiation gives password suppression for free. Guessing at it puts the
password on screen.

---

## Logon actions

Telnet has no authentication in the protocol, and neither does a serial line.
There is a login prompt, and something has to type at it. A stored credential
is therefore worth nothing until a sequence sends it — which is why an
imported telnet tree needs this to be usable rather than merely present.

A sequence is a list of steps:

| Field | Meaning |
|---|---|
| **Wait for** | A case-insensitive substring. `\|` separates alternatives, any of which satisfies the step. Empty means send immediately. |
| **Then send** | What to type. Understands `%USERNAME%`, `%PASSWORD%`, and the escapes `\r`, `\n`, `\t`. |

The default, used when a connection stores a password and says nothing about
how to use it:

```
wait for  ogin:|sername:   send  %USERNAME%\r
wait for  assword:         send  %PASSWORD%\r
```

The clipped prompts are the point: `ogin:` matches both `Login:` and `login:`,
and the alternation matches Cisco's `Username:` as well. Steps run in order, so
a sequence waiting only for `ogin:` stalls forever in front of a device that
says `Username:`.

> **Use `%PASSWORD%`, not the password.** Settings are stored as an
> unencrypted JSON document — fine for a font size, not for a credential. The
> placeholder is substituted at connect time from the credential the
> connection already names, decrypted under your vault key and never written
> down. A literal password typed into a step is a plaintext password in the
> database.

**The exchange happens in your own terminal**, not before it opens. The login
appears in the scrollback exactly as though you had typed it, because an
automated login nobody can see is an automated login nobody can check. Start
typing and the automation stops — continuing would fight you for the keyboard,
and the classic result is a password sent into a shell prompt and from there
into the device's command history.

Sequences are inherited from folders. A folder of three hundred switches with
one login is the case this exists for. An explicitly empty sequence on one
connection is how that one opts out.

---

## Serial lines

**Off by default**, and it should stay off almost everywhere.

A serial port only does anything where the machine running bkd is physically
cabled to the device. For a central install serving a company that is
essentially never; a lab box on somebody's bench is the case it exists for.
For a rack reached over the network, use a console server.

### Turning it on

Two settings, and both are required:

```yaml
policy:
  allow_serial: true

serial:
  allowed_devices:
    - "/dev/ttyUSB*"
    - "/dev/ttyS[0-3]"
```

The device path comes from a saved connection, which is to say from a user.
Without the allowlist, "open this path and stream it to my browser" is an
arbitrary-file read on a server holding every engineer's encrypted
credentials — and refusing anything that is not a character device does not
save it, because `/dev/mem` is one.

Three gates apply, all of them:

1. `policy.allow_serial`.
2. `serial.allowed_devices`, matched **after** symbolic links are resolved, so
   a link cannot reach past the globs. Empty opens nothing.
3. The opened file must be a character device, checked on the descriptor after
   opening rather than on the path before, so nothing can be swapped
   underneath in between.

bkd must also be able to read and write the device. On most distributions that
means adding its user to the `dialout` group:

```
usermod -aG dialout bkd
```

### Line settings

Blank means **9600 8N1, no handshaking**, which is what essentially all
network equipment ships with. Speed, parity and flow control are set on the
connection or inherited from its folder, and the terminal header shows what
was applied — `9600 8N1` is the first thing to check when a console shows
nothing but rubbish.

Flow control defaults to none deliberately: a three-wire console cable has no
handshake lines, and a port waiting for them is the other half of why a
console shows nothing.

### One wire, one terminal

A serial port is a single wire. The kernel will let two processes write to it
at once, and the result is two people's keystrokes interleaved character by
character into a device that has no idea anything is wrong — a switch
receiving `cofnigure tremrinal` and reporting a syntax error nobody typed.

So a line is claimed exclusively. A second attempt is refused, and the refusal
distinguishes your own other tab from a colleague's session, because those
need different responses.

---

## Console servers

A console server is a box with a serial port per device and a network
interface. Reaching line 12 means connecting to a port derived from 12 — over
telnet or SSH, both of which this already speaks. There is no new protocol
here, which is why the feature is a generator rather than a transport.

**Connections → Console server** asks for the appliance, how many lines it
has, and which login they share, then shows every connection it would create
before creating any of them.

| Appliance | Telnet | SSH |
|---|---|---|
| Opengear | 2000 + line | 3000 + line |
| Lantronix SLC / SLB | 2000 + line | 3000 + line |
| Avocent ACS / Cyclades | 7001 + line, counted from zero | reached as `user:port`, which this cannot generate |
| Digi | 2000 + line | — |

> **These are defaults, not laws.** Every one of these appliances lets somebody
> change them, and a rack set up in 2016 may well not match. The base port is
> editable, every resulting port is shown in the preview, and it is worth
> connecting to one line by hand before generating fifty.

Line numbers in generated names are padded to the width of the highest, so a
48-port appliance gives `line 01` through `line 48`. Not decoration: the tree
sorts by name, and unpadded numbers put line 10 between line 1 and line 2.

If generation stops part-way — a duplicate name, a folder that vanished — what
was already created is reported rather than rolled back. These are independent
connections, not one transaction, and the useful answer to "it stopped at line
31" is the list of thirty that worked.

---

## What telnet and serial cannot do

File transfer and tunnels are **channels on a multiplexed connection**. SSH has
channels; telnet and a serial line do not, so there is nothing to open. Both
features refuse those protocols with that reason rather than an error, and no
setting enables them — it is not a gap to be filled later.

Host key verification is likewise absent, and its absence is correct: neither
protocol has a host identity to verify. A fingerprint prompt for a telnet
connection would be theatre.
