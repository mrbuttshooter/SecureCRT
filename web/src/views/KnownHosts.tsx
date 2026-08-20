import { useCallback, useEffect, useState } from 'react'
import { api, type KnownHost } from '../api'

/**
 * KnownHosts shows which host keys are trusted, and lets a user withdraw
 * their own decisions.
 *
 * Worth having its own screen rather than being buried: someone who accepted
 * a fingerprint in a hurry and now doubts it needs somewhere to undo that,
 * and an entry published by an administrator needs to be visibly distinct so
 * it is clear why it cannot be removed here.
 */
export function KnownHosts() {
  const [hosts, setHosts] = useState<KnownHost[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ known_hosts: KnownHost[] }>('/api/known-hosts')
      setHosts(r.known_hosts ?? [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const forget = async (host: KnownHost) => {
    if (!window.confirm(
      `Forget the key for ${host.hostname}:${host.port}?\n\n` +
      'You will be asked to verify its fingerprint the next time you connect.',
    )) return

    try {
      await api.delete(`/api/known-hosts/${host.id}`)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (loading) return <p className="muted">Loading…</p>

  return (
    <section className="panel">
      <h2>Known hosts</h2>
      <p className="muted">
        The host keys you have accepted. If a host ever presents a different
        key, the connection is refused outright rather than prompting — no
        credential is sent.
      </p>

      {error && <div className="error">{error}</div>}

      {hosts.length === 0 ? (
        <p className="muted">No host keys have been accepted yet.</p>
      ) : (
        <table className="grid">
          <thead>
            <tr>
              <th>Host</th>
              <th>Key type</th>
              <th>Fingerprint</th>
              <th>Trusted</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => (
              <tr key={host.id}>
                <td>{host.hostname}:{host.port}</td>
                <td>{host.key_type}</td>
                <td><code className="fingerprint-inline">{host.fingerprint}</code></td>
                <td>{new Date(host.created_at).toLocaleDateString()}</td>
                <td>
                  {host.org_wide ? (
                    <span className="tag" title="Published by an administrator">
                      organisation-wide
                    </span>
                  ) : (
                    <button className="link danger" onClick={() => void forget(host)}>
                      Forget
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
