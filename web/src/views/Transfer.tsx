import { useEffect, useRef, useState } from 'react'
import {
  ApiError, api, exportConnections, previewImport,
  type ExportFormat, type ImportPreview, type ImportResult,
  type ImportSource, type PortabilityConfig,
} from '../api'

/**
 * Transfer is the import and export screen.
 *
 * Import is deliberately two steps. The first says what would happen — how
 * many connections, which names collide, what could not be carried across —
 * and writes nothing. The second applies exactly what was described. An
 * import goes into somebody's working device list, and "I restored the wrong
 * file" should be caught by reading rather than by undoing.
 */
export function Transfer() {
  const [config, setConfig] = useState<PortabilityConfig | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void api.get<PortabilityConfig>('/api/portability/config')
      .then(setConfig)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
  }, [])

  if (!config) {
    return <p className="muted">{error ?? 'Loading…'}</p>
  }

  return (
    <section className="transfer">
      {error && (
        <div className="error">
          {error} <button className="link" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      <ImportPanel config={config} />
      <hr />
      <ExportPanel config={config} />
    </section>
  )
}

// --- import ------------------------------------------------------------------

const SOURCES: { value: ImportSource; label: string; hint: string; archive: boolean }[] = [
  {
    value: 'securecrt', label: 'SecureCRT', archive: true,
    hint: 'Zip your SecureCRT configuration folder — the one containing a ' +
      'Sessions directory — and upload it. Saved passwords come across too.',
  },
  {
    value: 'ssh_config', label: 'OpenSSH (~/.ssh)', archive: true,
    hint: 'Zip your .ssh directory. The config, the private keys it names and ' +
      'known_hosts all come across.',
  },
  {
    value: 'putty', label: 'PuTTY', archive: false,
    hint: 'A .reg export of HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions, ' +
      'or a zip holding your sessions and your .ppk key files. PuTTY stores no ' +
      'passwords. Any .ppk in the zip is converted to an OpenSSH key for you.',
  },
  {
    value: 'csv', label: 'Spreadsheet (CSV)', archive: false,
    hint: 'A host list with columns for hostname, and optionally name, user, ' +
      'port, folder and password.',
  },
  {
    value: 'bundle', label: 'A bkd bundle', archive: false,
    hint: 'A .bkbundle exported from bkd. You will need its passphrase.',
  },
]

function ImportPanel({ config }: { config: PortabilityConfig }) {
  const [source, setSource] = useState<ImportSource>('securecrt')
  const [passphrase, setPassphrase] = useState('')
  const [configPassphrase, setConfigPassphrase] = useState('')
  const [keyPassphrase, setKeyPassphrase] = useState('')
  const [importKeys, setImportKeys] = useState(true)
  const [importKnownHosts, setImportKnownHosts] = useState(true)
  const [skipPasswords, setSkipPasswords] = useState(false)

  const [preview, setPreview] = useState<ImportPreview | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)
  const [onConflict, setOnConflict] = useState('skip')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fileInput = useRef<HTMLInputElement>(null)
  const chosen = SOURCES.find((s) => s.value === source)!

  const upload = async (file: File) => {
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setPreview(await previewImport(file, source, {
        passphrase,
        config_passphrase: configPassphrase,
        key_passphrase: keyPassphrase,
        import_keys: String(importKeys),
        import_known_hosts: String(importKnownHosts),
        skip_passwords: String(skipPasswords),
      }))
    } catch (err) {
      setPreview(null)
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const commit = async () => {
    if (!preview) return
    setBusy(true)
    setError(null)
    try {
      const response = await api.post<{ result: ImportResult }>('/api/portability/import', {
        token: preview.token,
        on_conflict: onConflict,
      })
      setResult(response.result)
      setPreview(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const discard = async () => {
    if (!preview) return
    try {
      await api.delete(`/api/portability/staged/${preview.token}`)
    } finally {
      setPreview(null)
    }
  }

  return (
    <div>
      <h2>Import</h2>
      <p className="muted">
        Bring your connections across from whatever you use now. Nothing is
        written until you have seen what would happen.
      </p>

      {error && <div className="error">{error}</div>}

      <div className="card">
        <label>
          <span>Where from</span>
          <select
            value={source}
            onChange={(e) => {
              setSource(e.target.value as ImportSource)
              setPreview(null)
              setResult(null)
            }}
          >
            {SOURCES.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </label>

        <p className="muted">{chosen.hint}</p>

        {source === 'bundle' && (
          <label>
            <span>Bundle passphrase</span>
            <input type="password" value={passphrase} autoComplete="off"
                   onChange={(e) => setPassphrase(e.target.value)} />
          </label>
        )}

        {source === 'securecrt' && (
          <>
            <label>
              <span>SecureCRT configuration passphrase (only if you set one)</span>
              <input type="password" value={configPassphrase} autoComplete="off"
                     onChange={(e) => setConfigPassphrase(e.target.value)} />
            </label>
            <label className="inline">
              <input type="checkbox" checked={skipPasswords}
                     onChange={(e) => setSkipPasswords(e.target.checked)} />
              Leave the saved passwords behind
            </label>
          </>
        )}

        {source === 'putty' && (
          <label>
            <span>Key passphrase (only if your .ppk files have one)</span>
            <input type="password" value={keyPassphrase} autoComplete="off"
                   onChange={(e) => setKeyPassphrase(e.target.value)} />
          </label>
        )}

        {source === 'ssh_config' && (
          <>
            <label className="inline">
              <input type="checkbox" checked={importKeys}
                     onChange={(e) => setImportKeys(e.target.checked)} />
              Import the private keys the config names
            </label>
            <label className="inline">
              <input type="checkbox" checked={importKnownHosts}
                     onChange={(e) => setImportKnownHosts(e.target.checked)} />
              Import known_hosts, so you are not asked to verify every host again
            </label>
          </>
        )}

        <div className="row">
          <input
            ref={fileInput}
            type="file"
            aria-label="Configuration to import"
            accept={chosen.archive ? '.zip' : undefined}
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) void upload(file)
              e.target.value = ''
            }}
          />
          {busy && <span className="muted">Reading…</span>}
        </div>
      </div>

      {preview && (
        <div className="card">
          <h3>What this would do</h3>

          <dl className="facts">
            <dt>Connections</dt>
            <dd>{preview.plan.new_sessions.length} new</dd>
            <dt>Folders</dt>
            <dd>{preview.plan.new_folders.length} new</dd>
            <dt>Credentials</dt>
            <dd>
              {preview.plan.counts.credentials}
              {preview.plan.counts.credentials > 0 && !preview.plan.has_secrets &&
                ' — without keys or passwords'}
            </dd>
            {preview.plan.counts.known_hosts > 0 && (
              <>
                <dt>Host keys</dt>
                <dd>{preview.plan.counts.known_hosts}</dd>
              </>
            )}
          </dl>

          {preview.notes.length > 0 && (
            <ul className="notes">
              {preview.notes.map((note, i) => <li key={i}>{note}</li>)}
            </ul>
          )}

          {preview.plan.conflicts.length > 0 && (
            <div className="warn">
              <p>
                {preview.plan.conflicts.length} names already exist here, starting
                with “{preview.plan.conflicts[0]?.name}”.
              </p>
              <label>
                <span>What to do with those</span>
                <select value={onConflict} onChange={(e) => setOnConflict(e.target.value)}>
                  <option value="skip">Leave what is already here alone</option>
                  <option value="rename">Import alongside, with a suffix</option>
                </select>
              </label>
            </div>
          )}

          {(preview.warnings.length > 0 || preview.plan.warnings.length > 0) && (
            <div className="warn">
              <p><strong>Worth reading before you commit:</strong></p>
              <ul>
                {[...preview.plan.warnings, ...preview.warnings].map((warning, i) => (
                  <li key={i}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="row">
            <button className="primary" onClick={() => void commit()} disabled={busy}>
              {busy ? 'Importing…' : 'Import'}
            </button>
            <button onClick={() => void discard()} disabled={busy}>Discard</button>
          </div>
        </div>
      )}

      {result && (
        <div className="card">
          <h3>Imported</h3>
          <p>
            {result.sessions} connections, {result.folders} folders,{' '}
            {result.credentials} credentials
            {result.known_hosts > 0 && `, ${result.known_hosts} host keys`}.
            {result.skipped > 0 && ` ${result.skipped} were skipped as duplicates.`}
          </p>
          {result.warnings.length > 0 && (
            <ul className="notes">
              {result.warnings.map((warning, i) => <li key={i}>{warning}</li>)}
            </ul>
          )}
        </div>
      )}

      <p className="muted">
        Maximum upload {Math.round(config.max_upload_bytes / (1024 * 1024))} MiB.
      </p>
    </div>
  )
}

// --- export ------------------------------------------------------------------

const FORMATS: { value: ExportFormat; label: string; hint: string }[] = [
  {
    value: 'bundle', label: 'Encrypted bundle (.bkbundle)',
    hint: 'Everything, sealed under a passphrase you choose. The only format ' +
      'that is safe to email or carry on a memory stick.',
  },
  {
    value: 'ssh_config', label: 'OpenSSH config',
    hint: 'A ~/.ssh/config. Names key files rather than carrying them, and ' +
      'cannot express a password at all.',
  },
  {
    value: 'securecrt', label: 'SecureCRT session files',
    hint: 'To go back. Passwords are obfuscated the way SecureCRT obfuscates ' +
      'them, which is to say barely.',
  },
  {
    value: 'putty_reg', label: 'PuTTY registry file',
    hint: 'A .reg to import on Windows. No passwords: PuTTY stores none.',
  },
  { value: 'json', label: 'JSON', hint: 'The whole structure, unencrypted.' },
  { value: 'csv', label: 'Spreadsheet (CSV)', hint: 'A host list. No keys.' },
]

function ExportPanel({ config }: { config: PortabilityConfig }) {
  const [format, setFormat] = useState<ExportFormat>('bundle')
  const [passphrase, setPassphrase] = useState('')
  const [repeat, setRepeat] = useState('')
  const [note, setNote] = useState('')
  const [includeSecrets, setIncludeSecrets] = useState(true)
  const [includeKnownHosts, setIncludeKnownHosts] = useState(true)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [warnings, setWarnings] = useState<string[]>([])

  const chosen = FORMATS.find((f) => f.value === format)!
  const isBundle = format === 'bundle'
  const carriesSecrets = config.formats_carrying_secret.includes(format)
  const plaintext = !isBundle

  // The policy switch is about credentials leaving the vault in the clear, so
  // it is the combination that is gated. A device list with no secrets in it
  // stays available whatever the switch says — that is how somebody goes back
  // to plain OpenSSH.
  const wouldCarrySecrets = carriesSecrets && includeSecrets
  const blockedByPolicy = plaintext && wouldCarrySecrets && !config.allow_plaintext_export
  const needsConfirmation = plaintext && wouldCarrySecrets

  const run = async () => {
    setError(null)
    setWarnings([])

    if (isBundle && passphrase !== repeat) {
      setError('The two passphrases do not match.')
      return
    }

    setBusy(true)
    try {
      const file = await exportConnections({
        format,
        include_secrets: includeSecrets && carriesSecrets,
        include_known_hosts: includeKnownHosts,
        passphrase: isBundle ? passphrase : undefined,
        note: isBundle ? note : undefined,
        confirm: needsConfirmation ? confirmed : undefined,
      })

      setWarnings(file.warnings)

      // A blob URL rather than a data URI: an export can be tens of
      // megabytes, and a data URI that size is refused by every browser.
      const url = URL.createObjectURL(file.blob)
      const link = document.createElement('a')
      link.href = url
      link.download = file.filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <h2>Export</h2>
      <p className="muted">
        Take everything with you. Nobody should be locked into this any more
        than into what it replaced.
      </p>

      {error && <div className="error">{error}</div>}

      <div className="card">
        <label>
          <span>Format</span>
          <select
            value={format}
            onChange={(e) => {
              setFormat(e.target.value as ExportFormat)
              setConfirmed(false)
              setWarnings([])
            }}
          >
            {FORMATS.map((f) => (
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
        </label>

        <p className="muted">{chosen.hint}</p>

        {isBundle && (
          <>
            <label>
              <span>Passphrase for the bundle</span>
              <input type="password" value={passphrase} autoComplete="new-password"
                     onChange={(e) => setPassphrase(e.target.value)} />
            </label>
            <label>
              <span>Repeat it</span>
              <input type="password" value={repeat} autoComplete="new-password"
                     onChange={(e) => setRepeat(e.target.value)} />
            </label>
            <p className="muted">
              At least {config.min_passphrase_length} characters. Nothing but this
              protects the file, and there is no way to recover it — write it
              down somewhere safe before you press the button.
            </p>
            <label>
              <span>Note (optional)</span>
              <input value={note} placeholder="before the migration"
                     onChange={(e) => setNote(e.target.value)} />
            </label>
          </>
        )}

        {carriesSecrets && (
          <label className="inline">
            <input type="checkbox" checked={includeSecrets}
                   onChange={(e) => {
                     setIncludeSecrets(e.target.checked)
                     setConfirmed(false)
                   }} />
            Include keys and passwords
          </label>
        )}

        {blockedByPolicy && (
          <div className="warn">
            <p>
              Exporting keys and passwords in the clear is disabled on this
              server. Export an encrypted bundle instead, or untick
              &ldquo;Include keys and passwords&rdquo; to take the device list
              on its own.
            </p>
          </div>
        )}

        <label className="inline">
          <input type="checkbox" checked={includeKnownHosts}
                 onChange={(e) => setIncludeKnownHosts(e.target.checked)} />
          Include accepted host keys
        </label>

        {needsConfirmation && !blockedByPolicy && (
          <div className="warn">
            <p>
              <strong>This format is not encrypted.</strong> Anyone who obtains
              the file can read every password and private key in it. It is
              recorded in the audit log as a critical event.
            </p>
            <label className="inline">
              <input type="checkbox" checked={confirmed}
                     onChange={(e) => setConfirmed(e.target.checked)} />
              I understand what this file will contain
            </label>
          </div>
        )}

        {plaintext && !wouldCarrySecrets && (
          <p className="muted">
            This file is not encrypted, but it carries no keys or passwords —
            only the connections themselves.
          </p>
        )}

        <div className="row">
          <button className="primary" onClick={() => void run()}
                  disabled={busy || blockedByPolicy || (needsConfirmation && !confirmed)}>
            {busy ? 'Preparing…' : 'Export'}
          </button>
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="warn">
          <p><strong>What this format could not carry:</strong></p>
          <ul>
            {warnings.map((warning, i) => <li key={i}>{warning}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}
