# Migrating to Bridgekeeper

This is the practical guide for moving a team off SecureCRT, PuTTY or plain
OpenSSH, and for leaving again if you ever want to.

Two things are true throughout and worth reading before anything else:

- **Nothing is written until you have seen what would happen.** Every import
  produces a plan first — how many connections, which names already exist,
  whether any key material came across — and only then offers to apply it. The
  command line does the same: `bkd import` prints the plan and stops unless you
  pass `-commit`.

- **You can always leave.** Everything can be exported again, including an
  encrypted bundle that restores a whole account on another instance, and
  formats that go back to SecureCRT, PuTTY and OpenSSH. This is deliberate.
  A tool nobody can leave is a tool nobody should adopt.

---

## What comes across

| From | Connections | Folders | Passwords | Keys | Host keys |
|---|---|---|---|---|---|
| SecureCRT | yes | yes | **yes** | yes | no |
| PuTTY | yes | one folder | none stored | **yes, converted** | no |
| OpenSSH `~/.ssh` | yes | one folder | n/a | yes | yes |
| CSV | yes | one folder | if a column has them | no | no |
| `.bkbundle` | yes | yes | yes | yes | yes |

PuTTY stores no passwords at all, which is a point in its favour and means a
PuTTY import brings your device list and nothing that needs protecting.

---

## From SecureCRT

### 1. Find your configuration folder

In SecureCRT: **Options → Global Options → General → Configuration folder**.
The path is usually:

- Windows: `%APPDATA%\VanDyke\Config`
- macOS: `~/Library/Application Support/VanDyke/SecureCRT/Config`
- Linux: `~/.vandyke/SecureCRT/Config`

### 2. Zip it

Zip the whole folder. Zipping the folder itself rather than its contents is
fine — both shapes are understood.

### 3. Upload it

**Import / export → Import**, choose **SecureCRT**, pick the zip.

If you set a *configuration passphrase* in SecureCRT (Global Options → General
→ Configuration passphrase), enter it in the field that appears. Most
installations have none; if you are not sure, try without one first — a wrong
answer produces a clear message rather than a broken import.

### 4. Read the plan, then import

The plan names how many connections and folders would be created, whether any
saved passwords came across, and any names that already exist here.

### About those saved passwords

SecureCRT's saved passwords are not encrypted in any meaningful sense. Both
formats it has used are readable by anyone holding the file:

- The older format is Blowfish under two keys published in every SecureCRT
  installation. Knowing the file is enough.
- The newer "V2" format is AES-256 — under a key derived from your
  configuration passphrase, or from a **fixed empty string** if you never set
  one, with an all-zero IV either way. Two identical passwords encrypt to
  identical bytes.

This is not a criticism of the import; it is why the import exists. Once those
passwords are in your vault they are encrypted under a key derived from your
vault passphrase, which the server does not store. **After a successful
import, delete the copy of the configuration you uploaded**, and treat any
older copies on file shares and backup drives as compromised credentials —
because that is what they are.

If you would rather not bring them at all, tick **Leave the saved passwords
behind** and set credentials by hand afterwards.

---

## From PuTTY

PuTTY keeps sessions in the Windows registry and keys in `.ppk` files
elsewhere on disk. Bring both.

### Sessions

Export the registry branch:

```
reg export "HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions" putty.reg
```

Upload `putty.reg` with **PuTTY** selected.

### Sessions and keys together

A `.reg` carries settings only, so sessions arrive naming key files that are
not there. To bring the keys as well, put both in one zip:

```
putty/
  sessions/          <- the session files, or export the registry into here
  core.ppk
  edge.ppk
```

On Unix, `~/.putty` already has this shape. On Windows, make the folder
yourself and copy your `.ppk` files into it.

Upload the zip. Every `.ppk` in it is converted to an OpenSSH key — the same
thing PuTTYgen's **Export OpenSSH key** does, one file at a time — and each
session naming a key file is joined to it automatically.

If your keys are passphrase-protected, put the passphrase in the **Key
passphrase** field. PuTTY allows a different passphrase on each key: the ones
it fits are imported, and the rest are listed by name so you know exactly
which to do separately.

The converted keys are stored **without** a separate passphrase, because your
vault already encrypts them. A second passphrase on top would be protection
against nothing and one more thing to lose.

Version 2 and version 3 `.ppk` files are both read, RSA, ECDSA and ed25519.
Version 1 is refused: PuTTY withdrew it in 1999 because its integrity check
could be forged, and a file claiming to be one is either twenty-five years old
or an attempt to get a forged key past the check.

---

## From OpenSSH

Zip your `~/.ssh` directory and upload it with **OpenSSH** selected.

- Each `Host` block becomes a connection. `HostName`, `Port`, `User`,
  `IdentityFile` and `ProxyJump` all come across, and jump chains are rebuilt
  by name.
- A bare `Host *` block supplies defaults to the rest, as OpenSSH does.
- Private keys named by `IdentityFile` are imported if they are in the zip. An
  encrypted key is imported too — set its passphrase on the credential
  afterwards.
- `known_hosts` comes across, so you are not asked to re-verify every host you
  already trust. Hashed entries are skipped: their hostnames cannot be
  recovered, and an entry nobody can name is of no use in a list a person
  reads.

---

## From a spreadsheet

If your team keeps a device list in a spreadsheet, export it as CSV and import
that. Columns are matched by name, case-insensitively, and unrecognised
columns are ignored:

| What it becomes | Column headers matched |
|---|---|
| Hostname (**required**) | `hostname`, `host`, `address`, `ip address`, `ip`, `target` |
| Name | `name`, `session`, `session name`, `device`, `device name`, `display name`, `label`, `title`, `alias`, `description` |
| Username | `username`, `user`, `login`, `account` |
| Port | `port` |
| Folder | `folder`, `group`, `site`, `location` |
| Password | `password`, `pass`, `secret` |
| Protocol | `protocol`, `proto` |

Spaces and case are ignored, so `Device Name` and `devicename` are the same
column. If nothing matches the name list, anything else ending in "name" is
used instead — real spreadsheets arrive with "Switch Name" and "AP Name" far
more often than with "Name".

A row with no hostname is skipped rather than imported as something unusable,
and the count of skipped rows is reported.

Everything lands under one folder — "Imported" unless you name another — with
each distinct value in the folder column as a child of it. If a row carries a
password, the import says so and reminds you to delete the spreadsheet
afterwards: it is the copy nothing is protecting.

---

## Migrating a team

The interface moves one person's connections and only that person can drive
it. For eighty people, use the command line on the server.

```bash
# What would happen. Writes nothing.
bkd import -user alice@example.com -source securecrt -file alice-config.zip

# Do it.
bkd import -user alice@example.com -source securecrt -file alice-config.zip -commit
```

The vault passphrase is read from `BKD_VAULT_PASSPHRASE` if it is set, and
prompted for otherwise. So a whole team is a loop — though note what that
implies: you need each person's vault passphrase, which most teams will not
want. Two better patterns:

**Pre-load the device tree, let people bring their own credentials.**

```bash
for user in $(cut -d, -f1 team.csv); do
    bkd import -user "$user" -source csv -file inventory.csv -commit -no-secrets
done
```

`-no-secrets` imports connections and folders only. It needs no vault at all,
so it works for accounts that have never signed in — which on day one is all
of them. Each person adds their own keys and passwords afterwards.

**Or have people import their own configuration through the browser.** Send
them the top half of this document. It takes about two minutes each and no
administrator ever handles their passphrase.

### Options

| Flag | What it does |
|---|---|
| `-commit` | Actually write. Without it, the plan prints and nothing changes. |
| `-no-secrets` | Connections and folders only. No vault needed. |
| `-on-conflict skip\|rename\|replace` | What to do with names that already exist. Default `skip`. |
| `-into-folder <id>` | Put everything under an existing folder, so an import can be inspected before it is mixed into a live tree. |
| `-config-passphrase` | SecureCRT's configuration passphrase. |
| `-key-passphrase` | For encrypted PuTTY `.ppk` files. |
| `-bundle-passphrase` | For a `.bkbundle`. |
| `-folder <name>` | The folder a CSV or PuTTY import lands in. |
| `-skip-known-hosts` | Leave accepted host keys behind, so every host is re-verified here. |

---

## Folder defaults

A folder can carry a username, a port and a credential that everything inside
it inherits. Leave the field blank on a connection and it takes the folder's;
set it and the connection wins. Change the folder later and every connection
still inheriting follows it.

This is what makes a tree of three hundred switches manageable: the username
and the key are set once, on the folder, and a connection is a name and an
address.

**Exports resolve it, except the bundle.** `ssh_config`, PuTTY, SecureCRT and
CSV have no concept of a folder default, so a connection inheriting port 8022
is written as 8022 — the file has to reach the right service. A `.bkbundle`
carries the folders and their defaults instead, so restoring one reproduces
the inheritance rather than pinning every connection to whatever its folder
said on the day it was exported.

> **If you have used bkd before this version:** the port field on a folder had
> no effect until now. Connections created earlier all carry an explicit port,
> whether or not anybody typed one, and the upgrade deliberately leaves them
> alone — rewriting them would re-point every connection at whatever its
> folder happens to say. Clear the port on a connection to have it start
> inheriting.

## Exporting

### The encrypted bundle

**Import / export → Export → Encrypted bundle**, or:

```bash
bkd export -user alice@example.com -format bundle -out alice.bkbundle
```

The bundle passphrase comes from `-passphrase`, from `BKD_BUNDLE_PASSPHRASE`,
or from a prompt. Exports never overwrite: if the file already exists the
command stops rather than replacing whatever was there. `-out -` writes to
standard output, with progress on standard error, so it can be piped.

A `.bkbundle` carries everything — connections, folders, credentials, host
keys — sealed under a passphrase you choose at export time. It is the only
format safe to email or carry on a memory stick, and the one to use for moving
between instances or for a personal backup.

The first line of the file is readable JSON: format, version, when it was
made, who made it, your note, and how many of each record it holds. That is
deliberate, so somebody who finds the file in six months can tell what it is
without its passphrase. **It is also a disclosure**: the header names the
account it came from. Everything of substance — every hostname, username, key
and password — is in the encrypted half.

There is no recovery. Lose the passphrase and the bundle is noise. Write it
down somewhere safe before you press the button.

### Going back

| Format | Carries | Notes |
|---|---|---|
| OpenSSH config | connections, key *names* | Cannot express a password at all. Keys are named, not carried — export those separately. |
| SecureCRT `.ini` | connections, passwords | Passwords obfuscated the way SecureCRT obfuscates them, which is to say barely. |
| PuTTY `.reg` | connections | PuTTY stores no passwords. |
| JSON | everything | The most complete plaintext form. |
| CSV | connections, passwords | For a spreadsheet. |

None of these is encrypted. Each export reports what the format could not
express rather than dropping it silently.

### The plaintext gate

Exporting **with keys and passwords** in any of those formats requires:

1. `policy.allow_plaintext_export: true` on the server. It is off by default.
2. An explicit confirmation.
3. An audit event, recorded as critical. If the audit log cannot be written,
   the export is refused — a system that cannot record somebody taking every
   credential out of the vault in the clear must not be the thing that hands
   them over.

Exporting **without** secrets is not gated. A list of hostnames carries no
credentials, so the switch that exists to stop credentials leaving has nothing
to say about it — and that is how somebody goes back to plain OpenSSH.

---

## What does not come across

Stated plainly, because finding out later is worse:

| | Why |
|---|---|
| Terminal colour schemes and fonts | Format-specific; set them here in a few seconds. |
| Keyboard maps and key bindings | Same. |
| SecureCRT button bars | No equivalent yet; snippets arrive in Phase 7. |
| VBScript / Python / JScript automation | Nothing here runs them. Scripted automation arrives in Phase 7 in a sandboxed JS runtime, and porting will be a rewrite rather than a conversion. |
| Session logging settings | The connections come across; set logging afresh. |
| PuTTY proxy settings | Named in a warning at import. Set a jump host on the connection if it needs one. |
| Telnet and serial connections | Imported and stored, but no transport is wired to them until Phase 6. They will sit in your tree until then. |

---

## Verifying a migration

Worth doing once on one account before you do eighty.

1. Import a configuration you know well.
2. Check the count against what you expected. The plan states it before you
   commit, and the result states it after.
3. Open a connection that uses a saved password, and one that uses a key.
4. Export a bundle, and import it into a second instance — a scratch install
   with its own database and its own master key. Everything should arrive:
   same connections, same fingerprints, same passwords.

Step 4 is a test in the suite as well (`TestTheRoundTripThroughTheCommandLine`
in `internal/server`), run on every build against two genuinely separate
instances.

---

## When something goes wrong

**"That is not a zip archive."** The file has to be a zip. A `.7z`, a `.rar`
or a folder will not do.

**"That passphrase did not open your vault."** The vault passphrase, not the
sign-in password. They are different secrets on purpose: the server never
learns the vault one.

**"That preview has expired or was already used."** A preview is held for
fifteen minutes and consumed when it is committed. Upload the file again. It
is also dropped the moment you lock your vault, because it holds decrypted
passwords in memory and "lock" has to mean what it says.

**Some passwords did not come across.** Almost always the SecureCRT
configuration passphrase: without it the V2 passwords cannot be decrypted. The
import warns rather than failing, so the connections arrive and the passwords
do not. Re-import with the passphrase; use **rename** on conflicts if you want
to compare, or **skip** and set the passwords by hand.

**A `.ppk` did not import.** Check the warning — it names each file and says
whether it was encrypted with a passphrase you did not supply, encrypted with
a different one, or not a key file at all. If it is a version 1 key, open it
in PuTTYgen and save it again; the modern format has an integrity check the
old one lacks.
