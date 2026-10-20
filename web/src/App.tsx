import { useCallback, useEffect, useState } from 'react'
import { ApiError, api, type AuthConfig, type Whoami } from './api'
import { Brand } from './Brand'
import { WindowDialog } from './Chrome'
import { SignIn } from './views/SignIn'
import { MFAChallenge } from './views/MFAChallenge'
import { VaultGate } from './views/VaultGate'
import { Credentials } from './views/Credentials'
import { Sessions } from './views/Sessions'
import { Security } from './views/Security'
import { Workspace, type Page } from './views/Workspace'
import { KnownHosts } from './views/KnownHosts'
import { Files } from './views/Files'
import { Transfer } from './views/Transfer'
import { Tunnels } from './views/Tunnels'
import { Snippets } from './views/Snippets'
import { Transcripts } from './views/Transcripts'
import { Admin } from './views/Admin'

export type Theme = 'dark' | 'light' | 'system'

/**
 * A new key, so that everybody starts on the light window: the old one was
 * written on every load and so holds "dark" for anyone who never chose.
 */
const THEME_KEY = 'bkd.theme.v2'

const PAGE_TITLES: Record<Page, string> = {
  files: 'File transfer (SFTP)',
  tunnels: 'Port forwarding and tunnels',
  snippets: 'Snippets and button bar',
  credentials: 'Credentials: keys and passwords',
  hosts: 'Known hosts',
  recordings: 'Transcripts',
  transfer: 'Import and export',
  sessions: 'Sign-ins',
  security: 'Security and two-factor',
  admin: 'Administration',
}

/**
 * App decides what to show from a single whoami response.
 *
 * The server reports what the user must do next — second factor, vault
 * enrolment, vault unlock — rather than leaving the client to infer it from a
 * sequence of error codes. That keeps the two from disagreeing about the
 * state of a session, which is the usual source of a login loop.
 *
 * Once signed in there is one window, the terminal workspace, the way
 * SecureCRT has one. Everything else — credentials, the file browser, import
 * — opens from its menus as a window on top, and closing it puts you back
 * exactly where you were.
 */
export function App() {
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [me, setMe] = useState<Whoami | null>(null)
  const [loading, setLoading] = useState(true)
  const [fatal, setFatal] = useState<string | null>(null)
  const [page, setPage] = useState<Page | null>(null)

  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const stored = window.localStorage.getItem(THEME_KEY)
      return stored === 'dark' || stored === 'system' ? stored : 'light'
    } catch {
      return 'light'
    }
  })
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'system') root.removeAttribute('data-theme')
    else root.setAttribute('data-theme', theme)
    try { window.localStorage.setItem(THEME_KEY, theme) } catch { /* convenience only */ }
  }, [theme])

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

  const closePage = useCallback(() => setPage(null), [])

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
    <main className="app-window">
      {/*
        The workspace stays mounted for the whole signed-in life of the page.
        Unmounting it would dispose every xterm instance and lose the visible
        scrollback; the server would still hold the sessions, but "open the
        credentials window and close it again" must not wipe the screen.
      */}
      <Workspace
        active={page === null}
        me={me}
        theme={theme}
        onTheme={setTheme}
        onOpenPage={setPage}
        onLockVault={() => void api.post('/api/vault/lock').then(refresh)}
        onSignOut={() => void signOut()}
      />

      {page && (
        <WindowDialog title={PAGE_TITLES[page]} wide={page === 'files' || page === 'admin'}
                      onClose={closePage}>
          {page === 'files' && <Files />}
          {page === 'tunnels' && <Tunnels />}
          {page === 'snippets' && <Snippets />}
          {page === 'credentials' && <Credentials />}
          {page === 'hosts' && <KnownHosts />}
          {page === 'recordings' && <Transcripts />}
          {page === 'admin' && me.user.is_admin && <Admin />}
          {page === 'transfer' && <Transfer />}
          {page === 'sessions' && <Sessions />}
          {page === 'security' && <Security me={me} onChanged={refresh} />}
        </WindowDialog>
      )}
    </main>
  )
}
