import { useCallback, useEffect, useState } from 'react'
import { api, type SessionInfo } from '../api'

/**
 * Sessions exists so someone can notice a sign-in they do not recognise and
 * do something about it. That is the whole purpose, so the actions are on the
 * same screen as the list rather than buried in settings.
 */
export function Sessions() {
  const [items, setItems] = useState<SessionInfo[]>([])
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setError(null)
    try {
      const body = await api.get<{ sessions: SessionInfo[] | null }>('/api/sessions')
      setItems(body.sessions ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const revoke = async (s: SessionInfo) => {
    try {
      await api.delete(`/api/sessions/${encodeURIComponent(s.id)}`)
      setNotice('That session has been signed out.')
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const revokeOthers = async () => {
    try {
      const body = await api.post<{ revoked: number }>('/api/sessions/revoke-others')
      setNotice(
        body.revoked === 0
          ? 'There were no other sessions.'
          : `Signed out ${body.revoked} other session${body.revoked === 1 ? '' : 's'}.`,
      )
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const others = items.filter((s) => !s.current).length

  return (
    <section>
      <div className="spread">
        <h2>Where you are signed in</h2>
        {others > 0 && (
          <button className="danger" onClick={() => void revokeOthers()}>
            Sign out everywhere else
          </button>
        )}
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      {loading ? (
        <p className="muted">Loading…</p>
      ) : (
        <ul className="plain card">
          {items.map((s) => (
            <li key={s.id}>
              <div className="spread">
                <div>
                  <strong>{s.user_agent || 'Unknown device'}</strong>
                  {s.current && <> <span className="tag">this device</span></>}
                  <div className="muted">
                    {s.ip_address || 'unknown address'} ·{' '}
                    {s.auth_method === 'oidc' ? 'single sign-on' : 'password'}
                    {s.mfa_satisfied && ' · two-factor'}
                  </div>
                  <div className="muted">
                    signed in {new Date(s.created_at).toLocaleString()} ·
                    expires {new Date(s.expires_at).toLocaleString()}
                  </div>
                </div>
                {!s.current && (
                  <button className="danger" onClick={() => void revoke(s)}>Sign out</button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      <p className="muted">
        If you see a session you do not recognise, sign it out and then change
        your vault passphrase — that cuts off every other device as well.
      </p>
    </section>
  )
}
