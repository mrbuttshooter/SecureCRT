import { useState } from 'react'
import QRCode from 'qrcode'
import { api, type MFAConfirmation, type MFAEnrolment, type Whoami } from '../api'

export function Security({ me, onChanged }: { me: Whoami; onChanged: () => Promise<void> }) {
  return (
    <section>
      <h2>Security</h2>
      <TwoFactor me={me} onChanged={onChanged} />
      {me.vault.requires_passphrase && <ChangePassphrase />}
    </section>
  )
}

function TwoFactor({ me, onChanged }: { me: Whoami; onChanged: () => Promise<void> }) {
  const [enrolment, setEnrolment] = useState<MFAEnrolment | null>(null)
  const [qr, setQr] = useState<string>('')
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const begin = async () => {
    setError(null)
    setBusy(true)
    try {
      const body = await api.post<MFAEnrolment>('/api/mfa/enrol')
      setEnrolment(body)
      // Rendered client-side to a data URI: the secret never has to make a
      // second trip to the server just to be turned into an image.
      setQr(await QRCode.toDataURL(body.provisioning_uri, { margin: 1, width: 200 }))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const confirm = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const body = await api.post<MFAConfirmation>('/api/mfa/confirm', { code })
      setCodes(body.recovery_codes)
      setEnrolment(null)
      await onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  const disable = async () => {
    if (!window.confirm('Remove two-factor authentication from this account?')) return
    setError(null)
    try {
      await api.delete('/api/mfa')
      await onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (codes) {
    return (
      <div className="card">
        <h2>Save your recovery codes</h2>
        <div className="warn">
          These are shown once and cannot be retrieved later. Each one works a
          single time. They are the only way back in if you lose your
          authenticator — print them or put them in a password manager now.
        </div>
        <div className="codes">
          {codes.map((c) => <div key={c}>{c}</div>)}
        </div>
        <button className="primary" onClick={() => setCodes(null)}>
          I have saved them
        </button>
      </div>
    )
  }

  if (enrolment) {
    return (
      <div className="card">
        <h2>Set up your authenticator</h2>
        <p className="muted">Scan this with Microsoft Authenticator, Google Authenticator, 1Password or similar.</p>
        {qr && <div className="qr"><img src={qr} alt="QR code for authenticator setup" width={200} height={200} /></div>}
        <p className="muted">Or enter this secret by hand:</p>
        <p className="mono">{enrolment.secret}</p>
        {error && <div className="error">{error}</div>}
        <form onSubmit={(e) => void confirm(e)}>
          <label>
            <span>Enter the code it shows, to confirm it works</span>
            <input value={code} required autoFocus inputMode="numeric"
                   autoComplete="one-time-code" placeholder="000000"
                   onChange={(e) => setCode(e.target.value)} />
          </label>
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Checking…' : 'Confirm'}
          </button>
        </form>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="spread">
        <div>
          <h2>Two-factor authentication</h2>
          <p className="muted">
            {me.user.totp_enabled
              ? 'Enabled. You are asked for a code from your authenticator when you sign in.'
              : me.user.sso
                ? 'Not set up here. If your identity provider already performs multi-factor authentication, you will not be asked twice.'
                : 'Not set up. Strongly recommended for an account that can reach production systems.'}
          </p>
        </div>
        {me.user.totp_enabled ? (
          <button className="danger" onClick={() => void disable()}>Remove</button>
        ) : (
          <button className="primary" disabled={busy} onClick={() => void begin()}>
            {busy ? 'Starting…' : 'Set up'}
          </button>
        )}
      </div>
      {error && <div className="error">{error}</div>}
    </div>
  )
}

function ChangePassphrase() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setNotice(null)

    if (next !== confirm) {
      setError('The two new passphrases do not match.')
      return
    }

    setBusy(true)
    try {
      const body = await api.post<{ other_sessions_revoked: number }>(
        '/api/vault/passphrase',
        { current_passphrase: current, new_passphrase: next },
      )
      setNotice(
        body.other_sessions_revoked > 0
          ? `Passphrase changed. ${body.other_sessions_revoked} other session${body.other_sessions_revoked === 1 ? ' was' : 's were'} signed out.`
          : 'Passphrase changed.',
      )
      setCurrent(''); setNext(''); setConfirm('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <h2>Vault passphrase</h2>
      <p className="muted">
        Changing this re-encrypts the key that protects your credentials. Your
        stored keys and passwords are untouched, and every other device is
        signed out.
      </p>
      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}
      <form onSubmit={(e) => void submit(e)}>
        <label>
          <span>Current passphrase</span>
          <input type="password" value={current} required autoComplete="current-password"
                 onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label>
          <span>New passphrase</span>
          <input type="password" value={next} required autoComplete="new-password"
                 onChange={(e) => setNext(e.target.value)} />
        </label>
        <label>
          <span>Repeat the new passphrase</span>
          <input type="password" value={confirm} required autoComplete="new-password"
                 onChange={(e) => setConfirm(e.target.value)} />
        </label>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Changing…' : 'Change passphrase'}
        </button>
      </form>
    </div>
  )
}
