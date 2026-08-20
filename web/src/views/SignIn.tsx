import { useState } from 'react'
import { ApiError, api, type AuthConfig } from '../api'

/**
 * SignIn offers whichever methods this deployment has enabled.
 *
 * Single sign-on comes first when available, because it is the normal path;
 * the local form is break-glass access for when the identity provider is
 * unreachable, and is presented as such rather than as an equal alternative.
 */
export function SignIn({ config, onSignedIn }: {
  config: AuthConfig
  onSignedIn: () => Promise<void>
}) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [showLocal, setShowLocal] = useState(!config.sso_enabled)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.post('/api/auth/login', { email, password })
      await onSignedIn()
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

  return (
    <main className="centred">
      <h1>Bridgekeeper</h1>
      <p className="muted">Sign in to reach your saved sessions and keys.</p>

      {error && <div className="error">{error}</div>}

      {config.sso_enabled && (
        <div className="card">
          <a href="/api/auth/sso/start">
            <button className="primary" type="button">
              Sign in with {config.sso_provider_name}
            </button>
          </a>
        </div>
      )}

      {config.password_auth_enabled && (
        <>
          {config.sso_enabled && !showLocal && (
            <p>
              <button type="button" onClick={() => setShowLocal(true)}>
                Sign in with a password instead
              </button>
            </p>
          )}

          {showLocal && (
            <form className="card" onSubmit={(e) => void submit(e)}>
              {config.sso_enabled && (
                <p className="muted">
                  Password sign-in is for break-glass access when single sign-on is
                  unavailable.
                </p>
              )}
              <label>
                <span>Email address</span>
                <input type="email" value={email} autoComplete="username" required
                       onChange={(e) => setEmail(e.target.value)} />
              </label>
              <label>
                <span>Password</span>
                <input type="password" value={password} autoComplete="current-password" required
                       onChange={(e) => setPassword(e.target.value)} />
              </label>
              <button className="primary" type="submit" disabled={busy}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
            </form>
          )}
        </>
      )}

      {!config.sso_enabled && !config.password_auth_enabled && (
        <div className="error">
          No sign-in method is enabled on this system. An administrator needs to
          configure single sign-on or allow password sign-in.
        </div>
      )}
    </main>
  )
}
