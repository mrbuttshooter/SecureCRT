# Single sign-on with Microsoft Entra

This is the part of the system that cannot be verified without your tenant.
Everything else is covered by tests; this needs an administrator in the Azure
portal and about ten minutes.

Work through it in order. At the end, `bkd test-sso` tells you whether it
worked before anyone tries to sign in.

## Before you start

You need:

- An account that can create app registrations in Entra ID (Application
  Administrator, Cloud Application Administrator, or Global Administrator).
- The public URL your users will visit, e.g. `https://bkd.example.com`. It
  must be HTTPS.

## 1. Create the app registration

**Entra ID → App registrations → New registration.**

| Field | Value |
|---|---|
| Name | Whatever your team will recognise in the portal |
| Supported account types | **Accounts in this organizational directory only** |
| Redirect URI | Platform **Web**, value `https://<your-host>/api/auth/sso/callback` |

Single-tenant is the right choice unless you genuinely need guests from other
directories. If you pick a multi-tenant option, you **must** also populate
`allowed_tenants` in the configuration — otherwise any Microsoft account in
existence can sign in to your system. `bkd` refuses to start in that
combination rather than letting it happen quietly.

The redirect URI is compared as an opaque string. Scheme, host, path and
trailing slash all have to match exactly. This is the single most common
cause of a failed first attempt.

## 2. Record the identifiers

From the registration's **Overview** page:

- **Application (client) ID**
- **Directory (tenant) ID**

## 3. Create a client secret

**Certificates & secrets → Client secrets → New client secret.**

Copy the **Value** immediately — the portal will not show it again.

**Write the expiry date somewhere your team will see it.** An expired client
secret is the most common cause of single sign-on breaking overnight, and the
symptom is a sudden failure with nothing having changed on your side. Entra
does not warn you loudly.

## 4. Check API permissions

**API permissions** should list `openid`, `profile` and `email` under
Microsoft Graph, as delegated permissions. These are usually present by
default.

Nothing else is needed. This application does not read your directory, send
mail, or access any other Graph resource — if the portal is asking you to
grant more than this, something is wrong.

*(The `groups` claim is only needed for the role mapping planned in a later
phase. Skip it for now.)*

## 5. Configure bkd

In `/etc/bkd/config.yaml`:

```yaml
server:
  external_url: "https://bkd.example.com"   # must match the redirect URI host

auth:
  oidc:
    enabled: true
    issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
    client_id: "<application-client-id>"
    allowed_tenants: ["<tenant-id>"]
    auto_provision: true
    provider_name: "Microsoft"
```

Note the `/v2.0` suffix on the issuer. Without it, discovery fails.

**Do not put the client secret in this file.** Supply it through the
environment instead, so it does not sit in a file that is readable by anyone
who can read the config:

```ini
# /etc/systemd/system/bkd.service.d/secret.conf
[Service]
Environment=BKD_OIDC_CLIENT_SECRET=<the secret value>
```

Then `systemctl daemon-reload`.

## 6. Test before anyone else does

```sh
sudo -u bkd bkd test-sso --config /etc/bkd/config.yaml
```

This performs real discovery against your tenant. It reports Microsoft's own
error code when something is wrong, which is far more useful than a blank
sign-in page:

```
FAILED

  auth: OIDC discovery against https://login.microsoftonline.com/... failed:
  400 Bad Request: {"error":"invalid_tenant","error_description":"AADSTS900021: ..."}
```

On success it prints a sign-in URL you can open in a browser to try the whole
round trip yourself.

What the check **cannot** confirm, because only a real sign-in exercises it:

- the client secret is correct (discovery does not use it)
- the redirect URI is registered correctly
- your conditional access policies permit the sign-in

So do open that URL and sign in once before telling your team the system is
ready.

## 7. Decide who can sign in

With `auto_provision: true`, anyone in your tenant who signs in gets an
account. That is usually what you want for an internal tool, and it is the
default.

To restrict it, set `auto_provision: false` and pre-create accounts. A
directory user with no account then sees a clear message telling them to ask
an administrator, rather than a failure.

## 8. Decide how vaults unlock

This is the decision worth putting in front of whoever owns security. See
[`SECURITY.md`](SECURITY.md) for the full reasoning.

```yaml
vault:
  sso_unlock_mode: passphrase      # or server_managed
```

`passphrase` (the default) means a user types a vault passphrase once per
working day after signing in with Microsoft. In exchange, a stolen database —
even together with the server master key — reveals nothing.

`server_managed` means signing in with Microsoft opens everything. It is what
most commercial web-SSH products do and it is a defensible choice, but it
gives up that guarantee entirely. `bkd` logs a warning at every startup in
this mode so the trade-off stays visible.

## Common failures

| Symptom | Cause |
|---|---|
| `AADSTS900021: Requested tenant identifier ... is not valid` | The tenant ID in the issuer URL is wrong or a placeholder |
| `AADSTS50011: redirect URI ... does not match` | The registered redirect URI differs from `external_url` + `/api/auth/sso/callback` — check scheme and trailing slash |
| `AADSTS7000215: Invalid client secret` | The secret is wrong, or has expired |
| `AADSTS53003: Blocked by Conditional Access` | A policy is blocking the sign-in; the user sees this message rather than a blank page |
| Discovery times out | Outbound HTTPS to `login.microsoftonline.com` is blocked, or a TLS-intercepting proxy's certificate is not trusted on this host |
| Sign-in loops back to the login page | `external_url` does not match the address users actually visit, so the session cookie is being set on a different host |

## Break-glass access

Keep at least one local administrator account. When the client secret
expires, or Entra is unreachable, or a conditional access change locks
everyone out, it is the only way back in.

```sh
sudo -u bkd bkd admin create-user --config /etc/bkd/config.yaml \
    -email breakglass@example.com -admin
```

Store that password wherever your team keeps emergency credentials — not in
this system, for the obvious reason.
