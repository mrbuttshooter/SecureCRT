import { useCallback, useEffect, useState } from 'react'
import {
  ApiError, api,
  type AdminTerminal, type AuditEvent, type Team, type TeamMember,
} from '../api'
import { TranscriptViewer } from './TranscriptViewer'

/**
 * Admin is the operator's room: who is connected right now, every recording,
 * the audit trail, and the teams that drive the shared tree. Every panel
 * reads data the server already had — this is the window that was missing,
 * not new tracking.
 *
 * Reachable only by administrators; the tab that opens it is rendered only
 * for them, and every endpoint behind it is gated server-side regardless.
 */
export function Admin() {
  const [panel, setPanel] = useState<'live' | 'transcripts' | 'audit' | 'teams'>('live')

  return (
    <section>
      <div className="spread">
        <h2>Admin</h2>
      </div>

      <nav className="subtabs">
        <button aria-current={panel === 'live' ? 'page' : undefined}
                onClick={() => setPanel('live')}>Live sessions</button>
        <button aria-current={panel === 'transcripts' ? 'page' : undefined}
                onClick={() => setPanel('transcripts')}>Transcripts</button>
        <button aria-current={panel === 'audit' ? 'page' : undefined}
                onClick={() => setPanel('audit')}>Audit log</button>
        <button aria-current={panel === 'teams' ? 'page' : undefined}
                onClick={() => setPanel('teams')}>Teams</button>
      </nav>

      {panel === 'live' && <LiveSessions />}
      {panel === 'transcripts' && <AdminTranscripts />}
      {panel === 'audit' && <AuditLog />}
      {panel === 'teams' && <Teams />}
    </section>
  )
}

/** duration renders "2h 14m" from a start time — the question SINCE never answered. */
function duration(from: string): string {
  const ms = Date.now() - new Date(from).getTime()
  if (ms < 0) return '—'
  const mins = Math.floor(ms / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ${mins % 60}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
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

  const terminate = async (t: AdminTerminal) => {
    if (!window.confirm(
      `End ${t.user_email}'s session on ${t.host || t.device}? Their terminal closes immediately.`)) return
    try {
      await api.delete(`/api/admin/terminals/${t.id}`)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (error) return <div className="error">{error}</div>
  if (rows === null) return <p className="muted">Loading…</p>
  if (rows.length === 0) {
    return (
      <div className="card">
        <p>Nobody is connected right now.</p>
        <p className="muted">This list refreshes every five seconds.</p>
      </div>
    )
  }

  return (
    <table className="grid">
      <thead>
        <tr>
          <th>User</th><th>Where</th><th>Protocol</th>
          <th>Connected for</th><th>State</th><th aria-label="Actions"></th>
        </tr>
      </thead>
      <tbody>
        {rows.map((t) => (
          <tr key={t.id}>
            <td className="nowrap">{t.user_email}</td>
            <td className="mono nowrap">{t.host || t.device}{t.port ? `:${t.port}` : ''}</td>
            <td className="nowrap">
              {t.protocol}
              {!t.encrypted && <> <span className="tag warn-tag">clear</span></>}
              {t.recorded && <> <span className="tag warn-tag">rec</span></>}
            </td>
            <td className="nowrap">{duration(t.created_at)}</td>
            <td className="nowrap">
              <span className={'pill pill-' + (t.closed ? 'ended' : 'live')}>
                {t.closed ? 'ended' : t.attached ? 'in use' : 'background'}
              </span>
            </td>
            <td className="nowrap">
              {!t.closed && (
                <button className="link danger" onClick={() => void terminate(t)}>
                  Terminate
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

interface AdminTranscriptRow {
  user_id: string
  user_email: string
  name: string
  size: number
  modified: string
}

function AdminTranscripts() {
  const [rows, setRows] = useState<AdminTranscriptRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [viewing, setViewing] = useState<AdminTranscriptRow | null>(null)

  useEffect(() => {
    void api
      .get<{ transcripts: AdminTranscriptRow[] }>('/api/admin/transcripts')
      .then((r) => setRows(r.transcripts ?? []))
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err))
        setRows([])
      })
  }, [])

  if (error) return <div className="error">{error}</div>
  if (rows === null) return <p className="muted">Loading…</p>
  if (rows.length === 0) {
    return (
      <div className="card">
        <p>No recordings yet, from anyone.</p>
        <p className="muted">
          Sessions are recorded when a user presses Record, when a connection
          has "keep a transcript" set, or — for every session — when
          record_all_sessions is enabled in this server's policy.
        </p>
      </div>
    )
  }

  return (
    <>
      <p className="muted">
        Opening a transcript is itself recorded in the audit log.
      </p>
      <table className="grid">
        <thead>
          <tr><th>User</th><th>Recorded</th><th>Session</th><th>Size</th><th aria-label="Actions"></th></tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.user_id + t.name}>
              <td className="nowrap">{t.user_email}</td>
              <td className="nowrap">{isoTime(t.modified)}</td>
              <td className="mono">{sessionFrom(t.name)}</td>
              <td className="nowrap">{formatSize(t.size)}</td>
              <td className="nowrap">
                <button className="link" onClick={() => setViewing(t)}>View</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {viewing && (
        <TranscriptViewer
          url={`/api/admin/transcripts/${encodeURIComponent(viewing.user_id)}/${encodeURIComponent(viewing.name)}`}
          title={`${viewing.user_email} · ${sessionFrom(viewing.name)}`}
          onClose={() => setViewing(null)}
        />
      )}
    </>
  )
}

/** The connection name buried in a transcript filename, for humans. */
function sessionFrom(name: string): string {
  return name.replace(/^[0-9]{8}-[0-9]{6}-/, '').replace(/[.]log$/, '')
}

function isoTime(v: string): string {
  const d = new Date(v)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

interface RosterUser {
  id: string
  email: string
}

function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null)
  const [actions, setActions] = useState<string[]>([])
  const [roster, setRoster] = useState<RosterUser[]>([])
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [since, setSince] = useState('')
  const [nextUntil, setNextUntil] = useState('')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async (until?: string) => {
    try {
      const params = new URLSearchParams()
      if (action) params.set('action', action)
      if (actor) params.set('actor', actor)
      if (since) params.set('since', new Date(since).toISOString())
      if (until) params.set('until', until)
      const r = await api.get<{
        events: AuditEvent[]; actions: string[] | null; next_until: string
      }>('/api/admin/audit?' + params.toString())
      setEvents((prev) => (until && prev ? [...prev, ...(r.events ?? [])] : r.events ?? []))
      if (r.actions) setActions(r.actions)
      setNextUntil(r.next_until ?? '')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setEvents([])
    }
  }, [action, actor, since])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    void api
      .get<{ users: RosterUser[] }>('/api/admin/users')
      .then((r) => setRoster(r.users ?? []))
      .catch(() => setRoster([]))
  }, [])

  const exportCSV = () => {
    if (!events?.length) return
    const head = 'occurred_at,actor,action,target,ip,outcome'
    const lines = events.map((e) => [
      e.occurred_at, e.actor_email, e.action,
      (e.target_label || e.target_id).replaceAll(',', ' '),
      e.ip, e.outcome,
    ].join(','))
    const blob = new Blob([head + '\n' + lines.join('\n')], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'bridgekeeper-audit.csv'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <>
      {error && <div className="error">{error}</div>}
      <div className="row audit-filters">
        <select value={actor} onChange={(e) => setActor(e.target.value)}
                aria-label="Filter by user">
          <option value="">Everyone</option>
          {roster.map((u) => (
            <option key={u.id} value={u.id}>{u.email}</option>
          ))}
        </select>
        <select value={action} onChange={(e) => setAction(e.target.value)}
                aria-label="Filter by action">
          <option value="">Every action</option>
          {actions.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <input type="date" value={since} aria-label="From date"
               onChange={(e) => setSince(e.target.value)} />
        <button onClick={() => exportCSV()} disabled={!events?.length}>Export CSV</button>
      </div>

      {events === null && <p className="muted">Loading…</p>}
      {events?.length === 0 && <div className="card"><p>No matching events.</p></div>}
      {events && events.length > 0 && (
        <>
          <table className="grid audit-table">
            <thead>
              <tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>From</th></tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap">{isoTime(e.occurred_at)}</td>
                  <td className="nowrap">{e.actor_email}</td>
                  <td className="mono nowrap">{e.action}</td>
                  <td>{e.target_label || shortID(e.target_id)}</td>
                  <td className="mono nowrap">{e.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {nextUntil && (
            <p>
              <button className="link" onClick={() => void load(nextUntil)}>
                Load older events
              </button>
            </p>
          )}
        </>
      )}
    </>
  )
}

/** A UUID nobody resolved still should not eat a table column. */
function shortID(id: string): string {
  return id.length > 12 ? id.slice(0, 8) + '…' : id
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

      <form className="row team-create" onSubmit={(e) => void create(e)}>
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
