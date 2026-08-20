import { useCallback, useEffect, useState } from 'react'
import { ApiError, api, type AuthConfig, type Whoami } from './api'
import { SignIn } from './views/SignIn'
import { MFAChallenge } from './views/MFAChallenge'
import { VaultGate } from './views/VaultGate'
import { Credentials } from './views/Credentials'
import { Sessions } from './views/Sessions'
import { Security } from './views/Security'

type Tab = 'credentials' | 'sessions' | 'security'

/**
 * App decides what to show from a single whoami response.
 *
 * The server reports what the user must do next — second factor, vault
 * enrolment, vault unlock — rather than leaving the client to infer it from a
 * sequence of error codes. That keeps the two from disagreeing about the
 * state of a session, which is the usual source of a login loop.
 */
export function App() {
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [me, setMe] = useState<Whoami | null>(null)
  const [loading, setLoading] = useState(true)
  const [fatal, setFatal] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('credentials')

  const refresh = useCallback(async () => {
    try {
      const who = await api.get<Whoami>('/api/auth/whoami')
      setMe(who)
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setMe(null)
      } else {
        setFatal(err instanceof Error ? err.message : String(err))
      }
    }
  }, [])

  useEffect(() => {
    void (async () => {
      try {
        // Fetching the sign-in configuration is also what issues the CSRF
        // token, so it has to happen before any state-changing request.
        setConfig(await api.get<AuthConfig>('/api/auth/config'))
        await refresh()
      } catch (err) {
        setFatal(err instanceof Error ? err.message : String(err))
      } finally {
        setLoading(false)
      }
    })()
  }, [refresh])

  if (loading) return <main className="centred"><p className="muted">Loading…</p></main>

  if (fatal) {
    return (
      <main className="centred">
        <h1>Bridgekeeper</h1>
        <div className="error">{fatal}</div>
        <p className="muted">
          The server may be unavailable. Reload once it is back.
        </p>
      </main>
    )
  }

  if (!config) return null

  if (!me) {
    return <SignIn config={config} onSignedIn={refresh} />
  }

  // Ordered by what blocks what: a second factor first, then the vault,
  // because vault operations need an authenticated session and the TOTP
  // secret itself is encrypted under the vault key.
  if (me.next.mfa) {
    return <MFAChallenge me={me} onDone={refresh} />
  }

  if (me.next.enrol_vault || !me.vault.unlocked) {
    return <VaultGate me={me} onDone={refresh} />
  }

  const signOut = async () => {
    try {
      await api.post('/api/auth/logout')
    } finally {
      await refresh()
    }
  }

  return (
    <main className="shell">
      <header className="bar">
        <div>
          <h1>Bridgekeeper</h1>
          <p className="muted">
            {me.user.display_name || me.user.email}
            {me.user.is_admin && <> · <span className="tag">administrator</span></>}
            {me.user.sso && <> · <span className="tag">single sign-on</span></>}
          </p>
        </div>
        <div className="row">
          <button onClick={() => void api.post('/api/vault/lock').then(refresh)}>
            Lock vault
          </button>
          <button onClick={() => void signOut()}>Sign out</button>
        </div>
      </header>

      <nav className="tabs">
        <button aria-current={tab === 'credentials' ? 'page' : undefined}
                onClick={() => setTab('credentials')}>Credentials</button>
        <button aria-current={tab === 'sessions' ? 'page' : undefined}
                onClick={() => setTab('sessions')}>Sessions</button>
        <button aria-current={tab === 'security' ? 'page' : undefined}
                onClick={() => setTab('security')}>Security</button>
      </nav>

      {tab === 'credentials' && <Credentials />}
      {tab === 'sessions' && <Sessions />}
      {tab === 'security' && <Security me={me} onChanged={refresh} />}
    </main>
  )
}
