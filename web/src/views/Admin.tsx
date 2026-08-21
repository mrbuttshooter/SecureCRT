import { useCallback, useEffect, useState } from 'react'
import {
  ApiError, api,
  type AdminTerminal, type AuditEvent, type Team, type TeamMember,
} from '../api'

/**
 * Admin is the operator's room: who is connected right now, the audit trail,
 * and the teams that drive the shared tree. Every panel here reads data the
 * server already had — this is the window that was missing, not new tracking.
 *
 * Reachable only by administrators; the tab that opens it is rendered only
 * for them, and every endpoint behind it is gated server-side regardless.
 */
export function Admin() {
  const [panel, setPanel] = useState<'live' | 'teams' | 'audit'>('live')

  return (
    <section>
      <div className="spread">
        <h2>Admin</h2>
      </div>

      <nav className="subtabs">
        <button aria-current={panel === 'live' ? 'page' : undefined}
                onClick={() => setPanel('live')}>Live sessions</button>
        <button aria-current={panel === 'teams' ? 'page' : undefined}
                onClick={() => setPanel('teams')}>Teams</button>
        <button aria-current={panel === 'audit' ? 'page' : undefined}
                onClick={() => setPanel('audit')}>Audit log</button>
      </nav>

      {panel === 'live' && <LiveSessions />}
      {panel === 'teams' && <Teams />}
      {panel === 'audit' && <AuditLog />}
    </section>
  )
}

function LiveSessions() {
  const [rows, setRows] = useState<AdminTerminal[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ terminals: AdminTerminal[] }>('/api/admin/terminals')
      setRows(r.terminals ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setRows([])
    }
  }, [])

  useEffect(() => {
    void load()
    // Live means live: the operator watching an incident wants it fresh.
    const id = window.setInterval(() => void load(), 5000)
    return () => window.clearInterval(id)
  }, [load])

  if (error) return <div className="error">{error}</div>
  if (rows === null) return <p className="muted">Loading…</p>
  if (rows.length === 0) return <div className="card"><p>Nobody is connected right now.</p></div>

  return (
    <table className="grid">
      <thead>
        <tr><th>User</th><th>Where</th><th>Protocol</th><th>Since</th><th>State</th></tr>
      </thead>
      <tbody>
        {rows.map((t) => (
          <tr key={t.id}>
            <td>{t.user_email}</td>
            <td className="mono">{t.host || t.device}{t.port ? `:${t.port}` : ''}</td>
            <td>
              {t.protocol}
              {!t.encrypted && <> <span className="tag warn-tag">clear</span></>}
              {t.recorded && <> <span className="tag warn-tag">rec</span></>}
            </td>
            <td>{new Date(t.created_at).toLocaleTimeString()}</td>
            <td>
              <span className={'pill pill-' + (t.closed ? 'ended' : 'live')}>
                {t.closed ? 'ended' : t.attached ? 'attached' : 'detached'}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Teams() {
  const [teams, setTeams] = useState<Team[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [open, setOpen] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ teams: Team[] }>('/api/teams')
      setTeams(r.teams ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setTeams([])
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const create = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    try {
      await api.post('/api/teams', { name: name.trim() })
      setName('')
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    }
  }

  const remove = async (team: Team) => {
    if (!window.confirm(`Delete the team “${team.name}”? Its shared folders and connections go with it.`)) return
    try {
      await api.delete(`/api/teams/${team.id}?confirm=true`)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    }
  }

  return (
    <>
      {error && <div className="error">{error}</div>}

      <form className="row" onSubmit={(e) => void create(e)}>
        <input placeholder="New team name" value={name}
               onChange={(e) => setName(e.target.value)} />
        <button className="primary" type="submit" disabled={!name.trim()}>Create team</button>
      </form>

      {teams === null && <p className="muted">Loading…</p>}
      {teams?.length === 0 && (
        <div className="card">
          <p>No teams yet.</p>
          <p className="muted">
            A team is a group of people who share a slice of the device tree.
            Create one, add members, then publish folders into it from the
            Terminal tab.
          </p>
        </div>
      )}

      {teams && teams.length > 0 && (
        <ul className="plain">
          {teams.map((team) => (
            <li key={team.id}>
              <div className="spread">
                <div>
                  <button className="link" onClick={() => setOpen(open === team.id ? null : team.id)}>
                    {team.name}
                  </button>
                  <span className="muted"> · {team.members ?? 0} member{team.members === 1 ? '' : 's'}</span>
                </div>
                <button className="link danger" onClick={() => void remove(team)}>Delete</button>
              </div>
              {open === team.id && <TeamMembers teamId={team.id} onChanged={load} />}
            </li>
          ))}
        </ul>
      )}
    </>
  )
}

function TeamMembers({ teamId, onChanged }: { teamId: string; onChanged: () => Promise<void> }) {
  const [members, setMembers] = useState<TeamMember[] | null>(null)
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ members: TeamMember[] }>(`/api/teams/${teamId}/members`)
      setMembers(r.members ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setMembers([])
    }
  }, [teamId])

  useEffect(() => { void load() }, [load])

  const add = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    try {
      await api.post(`/api/teams/${teamId}/members`, { email: email.trim() })
      setEmail('')
      await load()
      await onChanged()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    }
  }

  const remove = async (m: TeamMember) => {
    try {
      await api.delete(`/api/teams/${teamId}/members/${m.user_id}`)
      await load()
      await onChanged()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    }
  }

  return (
    <div className="card team-members">
      {error && <div className="error">{error}</div>}
      <form className="row" onSubmit={(e) => void add(e)}>
        <input type="email" placeholder="member@example.com" value={email}
               onChange={(e) => setEmail(e.target.value)} />
        <button type="submit" disabled={!email.trim()}>Add member</button>
      </form>
      {members?.length === 0 && <p className="muted">No members yet.</p>}
      {members && members.length > 0 && (
        <ul className="plain">
          {members.map((m) => (
            <li key={m.user_id}>
              <div className="spread">
                <span>{m.name || m.email} <span className="muted">· {m.email}</span></span>
                <button className="link danger" onClick={() => void remove(m)}>Remove</button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null)
  const [action, setAction] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const query = action ? `?action=${encodeURIComponent(action)}` : ''
      const r = await api.get<{ events: AuditEvent[] }>('/api/admin/audit' + query)
      setEvents(r.events ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setEvents([])
    }
  }, [action])

  useEffect(() => { void load() }, [load])

  return (
    <>
      {error && <div className="error">{error}</div>}
      <form className="row" onSubmit={(e) => { e.preventDefault(); void load() }}>
        <input placeholder="Filter by action, e.g. terminal.connected"
               value={action} onChange={(e) => setAction(e.target.value)} />
        <button type="submit">Search</button>
      </form>

      {events === null && <p className="muted">Loading…</p>}
      {events?.length === 0 && <div className="card"><p>No matching events.</p></div>}
      {events && events.length > 0 && (
        <table className="grid">
          <thead>
            <tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>From</th></tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.occurred_at).toLocaleString()}</td>
                <td>{e.actor_email}</td>
                <td className="mono">{e.action}</td>
                <td>{e.target_label || e.target_id}</td>
                <td className="mono">{e.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}
