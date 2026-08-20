import { useState } from 'react'
import { ApiError, api, type Whoami } from '../api'

/**
 * VaultGate handles both enrolment and unlocking.
 *
 * They share a screen because the user experiences them as the same moment —
 * "the thing standing between me and my keys" — and the only visible
 * difference is whether a passphrase is being chosen or recalled.
 */
export function VaultGate({ me, onDone }: { me: Whoami; onDone: () => Promise<void> }) {
  const enrolling = !me.vault.enrolled
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)

    if (enrolling && me.vault.requires_passphrase && passphrase !== confirm) {
      setError('The two passphrases do not match.')
      return
    }

    setBusy(true)
    try {
      await api.post(enrolling ? '/api/vault/enrol' : '/api/vault/unlock', { passphrase })
      await onDone()
    } catch (err) {
      if (err instanceof ApiError && err.code === 'rate_limited' && err.retryAfterSeconds) {
        const minutes = Math.ceil(err.retryAfterSeconds / 60)
        setError(`Too many attempts. Try again in about ${minutes} minute${minutes === 1 ? '' : 's'}.`)
      } else {
        setError(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(false)
    }
  }

  // Server-managed vaults need no passphrase at all, so there is nothing to
  // ask for — just a button to open it.
  if (!me.vault.requires_passphrase) {
    return (
      <main className="centred">
        <h1>{enrolling ? 'Set up your vault' : 'Unlock your vault'}</h1>
        <div className="warn">
          This system is configured so that signing in opens your vault
          automatically. Your credentials are protected by the server rather
          than by a passphrase only you know.
        </div>
        {error && <div className="error">{error}</div>}
        <button className="primary" disabled={busy}
                onClick={(e) => void submit(e)}>
          {busy ? 'Opening…' : 'Continue'}
        </button>
      </main>
    )
  }

  return (
    <main className="centred">
      <h1>{enrolling ? 'Set up your vault' : 'Unlock your vault'}</h1>

      {me.vault.was_reset && (
        <div className="warn">
          Your vault was reset by an administrator. Any credentials you had
          stored are gone and cannot be recovered — that is the same property
          that stops anyone reading them from a stolen database.
        </div>
      )}

      {enrolling ? (
        <p className="muted">
          Your vault passphrase encrypts every key and password you store here.
          It is never sent anywhere in a form the server can keep, so nobody —
          including an administrator — can recover it for you.
        </p>
      ) : (
        <p className="muted">
          {me.user.sso
            ? 'Signing in proves who you are. Your passphrase decrypts your keys, which is why both are needed.'
            : 'Enter your passphrase to decrypt your stored keys.'}
        </p>
      )}

      {error && <div className="error">{error}</div>}

      <form className="card" onSubmit={(e) => void submit(e)}>
        <label>
          <span>{enrolling ? 'Choose a passphrase' : 'Passphrase'}</span>
          <input type="password" value={passphrase} required autoFocus
                 autoComplete={enrolling ? 'new-password' : 'current-password'}
                 onChange={(e) => setPassphrase(e.target.value)} />
        </label>

        {enrolling && (
          <>
            <label>
              <span>Repeat it</span>
              <input type="password" value={confirm} required autoComplete="new-password"
                     onChange={(e) => setConfirm(e.target.value)} />
            </label>
            <p className="muted">
              At least 12 characters. A few unrelated words is both stronger and
              easier to remember than something short and complicated.
            </p>
          </>
        )}

        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Working…' : enrolling ? 'Create vault' : 'Unlock'}
        </button>
      </form>
    </main>
  )
}
