import { useCallback, useEffect, useState } from 'react'
import {
  ApiError, api,
  type SavedSession, type Tree, type Tunnel, type TunnelConfig, type TunnelKind,
} from '../api'
import { type HostKeyInfo } from '../terminal/socket'

/**
 * Tunnels forwards traffic over a connection you already have.
 *
 * Four shapes, and which of them this server offers is its operator's
 * decision rather than a fixed list — so the form asks the server first and
 * explains what is switched off instead of presenting a button that always
 * fails. Every refusal here has a named setting behind it, and saying which
 * one is the difference between a user filing a useful request and giving up.
 */
export function Tunnels() {
  const [config, setConfig] = useState<TunnelConfig | null>(null)
  const [tunnels, setTunnels] = useState<Tunnel[]>([])
  const [hosts, setHosts] = useState<SavedSession[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ tunnels: Tunnel[] }>('/api/tunnels')
      setTunnels(r.tunnels ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [])

  useEffect(() => {
    void (async () => {
      try {
        setConfig(await api.get<TunnelConfig>('/api/tunnels/config'))
        const tree = await api.get<Tree>('/api/tree')
        setHosts((tree.sessions ?? []).filter((s) => s.protocol === 'ssh'))
        await load()
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
      } finally {
        setLoading(false)
      }
    })()
  }, [load])

  // Byte counters move while a tunnel carries traffic, so the list refreshes
  // itself. Five seconds: often enough to look live, rare enough that a
  // hundred idle tabs are not a load problem.
  useEffect(() => {
    const timer = window.setInterval(() => void load(), 5000)
    return () => window.clearInterval(timer)
  }, [load])

  const close = async (tunnel: Tunnel) => {
    try {
      await api.delete(`/api/tunnels/${tunnel.id}`)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (loading) return <p className="muted">Loading…</p>

  return (
    <section className="panel">
      <h2>Tunnels</h2>
      <p className="muted">
        Reach a port on a device through a connection you already have. The
        SSH session carries the traffic, so nothing has to be installed on
        your machine and nothing new is exposed to the network the device is
        on.
      </p>

      {error && <div className="error">{error}</div>}

      {config && (
        <OpenTunnel
          config={config}
          hosts={hosts}
          onOpened={() => void load()}
          onError={setError}
        />
      )}

      <TunnelList tunnels={tunnels} onClose={close} />
    </section>
  )
}

/** Which kinds this server will open, with the reason when it will not. */
function availability(config: TunnelConfig): Record<TunnelKind, string | null> {
  return {
    web: config.web_enabled
      ? null
      : 'Unavailable: a device’s own pages cannot safely be served from this ' +
        'address, so they need a separate domain. An administrator sets ' +
        'tunnels.domain.',
    local: config.listeners_enabled
      ? null
      : 'Unavailable: opening a listening port on this server is switched off. ' +
        'An administrator can enable it with policy.allow_tcp_tunnels.',
    socks: config.listeners_enabled
      ? null
      : 'Unavailable: opening a listening port on this server is switched off. ' +
        'An administrator can enable it with policy.allow_tcp_tunnels.',
    remote: config.remote_enabled
      ? null
      : 'Unavailable: asking a device to listen on this server’s behalf is ' +
        'switched off. An administrator can enable it with ' +
        'policy.allow_remote_forwards.',
  }
}

const KINDS: { value: TunnelKind; label: string; blurb: string }[] = [
  {
    value: 'web',
    label: 'Device web interface',
    blurb:
      'Opens a switch or router’s own web page in your browser, through the ' +
      'SSH connection. Served from its own address so its pages can never ' +
      'reach into this application.',
  },
  {
    value: 'local',
    label: 'Port on this server',
    blurb:
      'Opens a port here that forwards to one address on the device’s ' +
      'network — for a database client, an RDP client, anything not HTTP. ' +
      'Anyone who can reach that port reaches what is behind it.',
  },
  {
    value: 'socks',
    label: 'SOCKS proxy',
    blurb:
      'The same port, but the destination comes per connection, so one ' +
      'tunnel reaches everything the device can. Point a browser or a client ' +
      'at it. CONNECT only.',
  },
  {
    value: 'remote',
    label: 'Port on the device',
    blurb:
      'The reverse: the device listens, and whatever connects there is ' +
      'carried back and dialled from this server. Loopback and link-local ' +
      'destinations are refused.',
  },
]

interface OpenTunnelProps {
  config: TunnelConfig
  hosts: SavedSession[]
  onOpened: () => void
  onError: (message: string | null) => void
}

function OpenTunnel(props: OpenTunnelProps) {
  const reasons = availability(props.config)
  const firstUsable = KINDS.find((k) => reasons[k.value] === null)?.value ?? 'web'

  const [kind, setKind] = useState<TunnelKind>(firstUsable)
  const [sessionId, setSessionId] = useState('')
  const [label, setLabel] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [remotePort, setRemotePort] = useState('')
  const [remoteBind, setRemoteBind] = useState('')
  const [opening, setOpening] = useState(false)
  const [fingerprint, setFingerprint] = useState<string | null>(null)

  const unavailable = reasons[kind]
  const chosen = KINDS.find((k) => k.value === kind)!
  const wantsDestination = kind === 'local' || kind === 'remote'

  const open = async (event: React.FormEvent, acceptHostKey?: string) => {
    event.preventDefault()
    props.onError(null)
    setOpening(true)

    try {
      await api.post<Tunnel>('/api/tunnels', {
        session_id: sessionId,
        kind,
        label: label.trim(),
        host: host.trim(),
        port: port ? Number(port) : 0,
        remote_bind: remoteBind.trim(),
        remote_port: remotePort ? Number(remotePort) : 0,
        accept_host_key: acceptHostKey ?? '',
      })
      setFingerprint(null)
      props.onOpened()
    } catch (err) {
      // A fingerprint prompt is not a failure. There is no socket here to ask
      // over, so the first attempt reports what it saw and the second carries
      // the answer — the same two-step the file browser uses.
      const hostKey = err instanceof ApiError
        ? (err.details.host_key as HostKeyInfo | undefined)
        : undefined
      if (hostKey?.fingerprint) {
        setFingerprint(hostKey.fingerprint)
      } else {
        props.onError(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setOpening(false)
    }
  }

  return (
    <form className="card editor" onSubmit={(e) => void open(e)}>
      <h3>Open a tunnel</h3>

      <label>
        Kind
        <select value={kind} onChange={(e) => setKind(e.target.value as TunnelKind)}>
          {KINDS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}{reasons[k.value] ? ' (unavailable)' : ''}
            </option>
          ))}
        </select>
      </label>
      <p className="muted">{chosen.blurb}</p>
      {unavailable && <div className="warn">{unavailable}</div>}

      <label>
        Through which connection
        <select value={sessionId} onChange={(e) => setSessionId(e.target.value)} required>
          <option value="">Choose a saved connection…</option>
          {props.hosts.map((h) => (
            <option key={h.id} value={h.id}>{h.name} · {h.hostname}</option>
          ))}
        </select>
      </label>

      <label>
        Label
        <input value={label} onChange={(e) => setLabel(e.target.value)}
               placeholder="switch web ui" />
      </label>

      {kind === 'web' && (
        <label>
          Port on the device
          <input value={port} onChange={(e) => setPort(e.target.value)}
                 inputMode="numeric" placeholder="80" />
        </label>
      )}

      {wantsDestination && (
        <div className="row">
          <label className="grow">
            {kind === 'remote'
              ? 'Address to reach from this server'
              : 'Address to reach on the device’s network'}
            <input value={host} onChange={(e) => setHost(e.target.value)}
                   placeholder="10.0.0.5" required />
          </label>
          <label>
            Port
            <input value={port} onChange={(e) => setPort(e.target.value)}
                   inputMode="numeric" placeholder="5432" required />
          </label>
        </div>
      )}

      {kind === 'remote' && (
        <div className="row">
          <label>
            Port on the device
            <input value={remotePort} onChange={(e) => setRemotePort(e.target.value)}
                   inputMode="numeric" placeholder="the device chooses" />
          </label>
          <label className="grow">
            Address the device binds
            <input value={remoteBind} onChange={(e) => setRemoteBind(e.target.value)}
                   placeholder="loopback on the device" />
          </label>
        </div>
      )}

      {fingerprint && (
        <div className="warn">
          <p>
            This host’s key has not been accepted before. Check the fingerprint
            against a source that did not come from the host itself.
          </p>
          <p><code className="fingerprint-inline">{fingerprint}</code></p>
          <button type="button" onClick={(e) => void open(e, fingerprint)}>
            Accept this key and open the tunnel
          </button>
        </div>
      )}

      <div className="row">
        <button type="submit" disabled={opening || unavailable !== null}>
          {opening ? 'Opening…' : 'Open tunnel'}
        </button>
      </div>
    </form>
  )
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = n / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

function TunnelList(props: { tunnels: Tunnel[]; onClose: (t: Tunnel) => void }) {
  if (props.tunnels.length === 0) {
    return <p className="muted">No tunnels are open.</p>
  }

  return (
    <table className="grid">
      <thead>
        <tr>
          <th>Label</th>
          <th>Kind</th>
          <th>Where to point a client</th>
          <th>Reaches</th>
          <th>Traffic</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {props.tunnels.map((t) => (
          <tr key={t.id}>
            <td>
              {t.label || <span className="muted">unlabelled</span>}
              {t.state !== 'open' && <span className="muted"> · {t.state}</span>}
              {t.error && <div className="error">{t.error}</div>}
              {t.via && t.via.length > 0 && (
                <div className="muted">via {t.via.map((h) => h.name).join(' → ')}</div>
              )}
            </td>
            <td>{KINDS.find((k) => k.value === t.kind)?.label ?? t.kind}</td>
            <td>
              {t.url ? (
                // rel=noreferrer as well as noopener: the device should not be
                // told which page sent the visitor.
                <a href={t.url} target="_blank" rel="noopener noreferrer">{t.url}</a>
              ) : t.listen ? (
                <code>{t.listen}</code>
              ) : (
                <span className="muted">—</span>
              )}
            </td>
            <td>{t.remote ? <code>{t.remote}</code> : <span className="muted">wherever asked</span>}</td>
            <td>
              {t.connections} connection{t.connections === 1 ? '' : 's'}
              {t.active > 0 && <> · {t.active} live</>}
              <div className="muted">↑ {bytes(t.bytes_up)} · ↓ {bytes(t.bytes_down)}</div>
            </td>
            <td>
              <button onClick={() => props.onClose(t)}>Close</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
