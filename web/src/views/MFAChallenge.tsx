import { useState } from 'react'
import { ApiError, api, type Whoami } from '../api'

/**
 * MFAChallenge asks for a second factor on a session that has not satisfied
 * one yet.
 *
 * Recovery codes are offered on the same screen rather than hidden behind a
 * link, because the person who needs one has usually just lost the device
 * that would have produced the other option.
 */
export function MFAChallenge({ me, onDone }: { me: Whoami; onDone: () => Promise<void> }) {
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.post(useRecovery ? '/api/mfa/recovery' : '/api/mfa/verify', { code })
      await onDone()
    } catch (err) {
      if (err instanceof ApiError && err.code === 'rate_limited' && err.retryAfterSeconds) {
        const minutes = Math.ceil(err.retryAfterSeconds / 60)
        setError(`Too many attempts. Try again in about ${minutes} minute${minutes === 1 ? '' : 's'}.`)
      } else {
        setError(err instanceof Error ? err.message : String(err))
      }
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  if (!me.user.totp_enabled) {
    return (
      <main className="centred">
        <h1>Two-factor authentication required</h1>
        <p>
          This system requires two-factor authentication, and this account has
          none set up yet.
        </p>
        <p className="muted">
          Setting it up needs an unlocked vault, because the secret is encrypted
          with your vault key. Unlock your vault first, then use the Security tab.
        </p>
      </main>
    )
  }

  return (
    <main className="centred">
      <h1>Two-factor authentication</h1>
      <p className="muted">
        {useRecovery
          ? 'Enter one of the recovery codes you saved when you set this up. Each works once.'
          : 'Enter the current code from your authenticator app.'}
      </p>

      {error && <div className="error">{error}</div>}

      <form className="card" onSubmit={(e) => void submit(e)}>
        <label>
          <span>{useRecovery ? 'Recovery code' : 'Six-digit code'}</span>
          <input
            value={code}
            required
            autoFocus
            autoComplete="one-time-code"
            inputMode={useRecovery ? 'text' : 'numeric'}
            placeholder={useRecovery ? 'BCDFG-HJKMN-PQRST-VWXYZ' : '000000'}
            onChange={(e) => setCode(e.target.value)}
          />
        </label>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Checking…' : 'Continue'}
        </button>
      </form>

      <p>
        <button type="button" onClick={() => { setUseRecovery(!useRecovery); setCode(''); setError(null) }}>
          {useRecovery ? 'Use my authenticator app instead' : 'I have lost my authenticator'}
        </button>
      </p>
    </main>
  )
}
