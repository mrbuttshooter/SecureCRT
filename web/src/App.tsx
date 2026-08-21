import { useCallback, useEffect, useState } from 'react'
import { ApiError, api, type AuthConfig, type Whoami } from './api'
import { Brand } from './Brand'
import { SignIn } from './views/SignIn'
import { MFAChallenge } from './views/MFAChallenge'
import { VaultGate } from './views/VaultGate'
import { Credentials } from './views/Credentials'
import { Sessions } from './views/Sessions'
import { Security } from './views/Security'
import { Workspace } from './views/Workspace'
import { KnownHosts } from './views/KnownHosts'
import { Files } from './views/Files'
import { Transfer } from './views/Transfer'
import { Tunnels } from './views/Tunnels'
import { Snippets } from './views/Snippets'

type Tab =
  | 'terminal' | 'files' | 'tunnels' | 'snippets' | 'credentials'
  | 'hosts' | 'transfer' | 'sessions' | 'security'

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
  const [tab, setTab] = useState<Tab>('terminal')

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
        <Brand />
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
    <>
      {/*
        One bar carries everything: brand, navigation, who is signed in, and
        the two session actions. It lives outside <main> so it spans the
        window whatever width the page below it keeps. On the screen someone
        lives in all day, the rows this saves are terminal rows.
      */}
      <header className="bar">
        <Brand />
        <nav className="tabs">
        <button aria-current={tab === 'terminal' ? 'page' : undefined}
                onClick={() => setTab('terminal')}>Terminal</button>
        <button aria-current={tab === 'files' ? 'page' : undefined}
                onClick={() => setTab('files')}>Files</button>
        <button aria-current={tab === 'tunnels' ? 'page' : undefined}
                onClick={() => setTab('tunnels')}>Tunnels</button>
        <button aria-current={tab === 'snippets' ? 'page' : undefined}
                onClick={() => setTab('snippets')}>Snippets</button>
        <button aria-current={tab === 'credentials' ? 'page' : undefined}
                onClick={() => setTab('credentials')}>Credentials</button>
        <button aria-current={tab === 'hosts' ? 'page' : undefined}
                onClick={() => setTab('hosts')}>Known hosts</button>
        <button aria-current={tab === 'transfer' ? 'page' : undefined}
                onClick={() => setTab('transfer')}>Import / export</button>
        <button aria-current={tab === 'sessions' ? 'page' : undefined}
                onClick={() => setTab('sessions')}>Signed in</button>
        <button aria-current={tab === 'security' ? 'page' : undefined}
                onClick={() => setTab('security')}>Security</button>
        </nav>
        <div className="who">
          <span className="name">{me.user.display_name || me.user.email}</span>
          {me.user.is_admin && <span className="tag">admin</span>}
          {me.user.sso && <span className="tag">sso</span>}
        </div>
        <div className="row">
          <button onClick={() => void api.post('/api/vault/lock').then(refresh)}>
            Lock vault
          </button>
          <button onClick={() => void signOut()}>Sign out</button>
        </div>
      </header>

      <main className={'shell' + (tab === 'terminal' || tab === 'files' ? ' shell-wide' : '')}>
      {/*
        The workspace stays mounted once it has been opened. Unmounting it to
        visit another tab would dispose every xterm instance and lose the
        visible scrollback — the server would still hold the sessions, but
        "switch tab and back" must not wipe the screen.
      */}
      <div hidden={tab !== 'terminal'} className="tabpanel">
        <Workspace active={tab === 'terminal'} />
      </div>
      {tab === 'files' && <Files />}
      {tab === 'tunnels' && <Tunnels />}
      {tab === 'snippets' && <Snippets />}
      {tab === 'credentials' && <Credentials />}
      {tab === 'hosts' && <KnownHosts />}
      {tab === 'transfer' && <Transfer />}
      {tab === 'sessions' && <Sessions />}
      {tab === 'security' && <Security me={me} onChanged={refresh} />}
      </main>
    </>
  )
}
