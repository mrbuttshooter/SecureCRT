// Client for the bkd API.
//
// Two things every call has to get right, so they live here rather than being
// repeated at each call site:
//
//   - Cookies must be sent. The session is a cookie, not a bearer token, so
//     `credentials: 'same-origin'` is not optional.
//   - State-changing requests must echo the CSRF cookie in a header. That
//     echo is the half of the double-submit check a cross-origin page cannot
//     perform.

export type ErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'internal_error'
  | 'vault_locked'
  | 'vault_not_set_up'
  | 'mfa_required'
  | 'invalid_code'
  | 'sso_disabled'
  | 'password_auth_disabled'
  | 'key_encrypted'
  | 'folder_not_empty'
  | 'host_key_prompt'
  | 'host_key_changed'
  | 'host_key_rejected'

/** ApiError carries the server's machine-readable code alongside its message. */
export class ApiError extends Error {
  readonly code: ErrorCode
  readonly status: number
  readonly retryAfterSeconds?: number

  /**
   * details is the rest of the server's error object.
   *
   * Some errors carry more than prose — a refused folder delete reports how
   * many folders and connections it would have destroyed, so the interface
   * can say exactly what is at stake rather than asking a vague "are you
   * sure?".
   */
  readonly details: Record<string, unknown>

  constructor(
    status: number,
    code: ErrorCode,
    message: string,
    retryAfterSeconds?: number,
    details: Record<string, unknown> = {},
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfterSeconds = retryAfterSeconds
    this.details = details
  }
}

const CSRF_COOKIE = 'bkd_csrf'
const CSRF_HEADER = 'X-CSRF-Token'

function readCookie(name: string): string {
  const prefix = `${name}=`
  for (const part of document.cookie.split('; ')) {
    if (part.startsWith(prefix)) return decodeURIComponent(part.slice(prefix.length))
  }
  return ''
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  if (method !== 'GET' && method !== 'HEAD') {
    const token = readCookie(CSRF_COOKIE)
    if (token) headers[CSRF_HEADER] = token
  }

  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  const text = await response.text()
  let parsed: unknown = undefined
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      // A non-JSON body from an API endpoint means something upstream
      // intervened — a proxy error page, most likely.
      if (!response.ok) {
        throw new ApiError(response.status, 'internal_error',
          `The server returned an unexpected response (${response.status}).`)
      }
    }
  }

  if (!response.ok) {
    const envelope = parsed as {
      error?: { code?: ErrorCode; message?: string; retry_after_seconds?: number }
    }
    const err = envelope?.error
    throw new ApiError(
      response.status,
      err?.code ?? 'internal_error',
      err?.message ?? `Request failed (${response.status}).`,
      err?.retry_after_seconds,
      (err ?? {}) as Record<string, unknown>,
    )
  }

  return parsed as T
}

export const api = {
  get: <T,>(path: string) => request<T>('GET', path),
  post: <T,>(path: string, body?: unknown) => request<T>('POST', path, body),
  patch: <T,>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  delete: <T,>(path: string) => request<T>('DELETE', path),
}

// --- response shapes --------------------------------------------------------

export interface AuthConfig {
  password_auth_enabled: boolean
  sso_enabled: boolean
  sso_provider_name: string
  mfa_policy: 'off' | 'optional' | 'required'
}

export interface Whoami {
  user: {
    id: string
    email: string
    display_name: string
    is_admin: boolean
    sso: boolean
    totp_enabled: boolean
  }
  session: {
    id: string
    auth_method: 'local' | 'oidc'
    mfa_satisfied: boolean
    expires_at: string
  }
  vault: {
    enrolled: boolean
    unlocked: boolean
    unlock_kind: string
    requires_passphrase: boolean
    was_reset: boolean
  }
  next: {
    mfa: boolean
    enrol_vault: boolean
    unlock_vault: boolean
    mfa_available: boolean
  }
}

export interface VaultStatus {
  enrolled: boolean
  unlocked: boolean
  unlock_kind: string
  requires_passphrase: boolean
  was_reset: boolean
  minimum_length: number
}

export interface Credential {
  id: string
  name: string
  kind: 'ssh_key' | 'password' | 'passphrase' | 'enable_secret'
  username: string
  public_key: string
  fingerprint: string
  key_type: string
  server_unlockable: boolean
  created_at: string
  updated_at: string
  last_used_at?: string
  notice?: string
}

export interface SessionInfo {
  id: string
  current: boolean
  auth_method: 'local' | 'oidc'
  user_agent: string
  ip_address: string
  mfa_satisfied: boolean
  created_at: string
  expires_at: string
}

export interface MFAEnrolment {
  secret: string
  provisioning_uri: string
  digits: number
  period_seconds: number
}

export interface MFAConfirmation {
  enabled: boolean
  recovery_codes: string[]
  warning: string
}

// --- saved connections ------------------------------------------------------

/**
 * Settings are per-connection options.
 *
 * Every field is optional in the same sense the server means it: absent is
 * "inherit from the folder", which is not the same as set to an empty value.
 * Sending `null` for a field clears it back to inherited.
 */
export interface Settings {
  username?: string | null
  port?: number | null
  credential_id?: string | null
  colour_scheme?: string | null
  font_size?: number | null
  scrollback?: number | null
  keepalive_seconds?: number | null
  log_session?: boolean | null

  /**
   * Keys to offer through a forwarded SSH agent. Empty or absent means none,
   * which is the only sensible default.
   *
   * Never inherited from a folder — the server refuses this on a folder
   * outright, because a default here would offer the keys to every host
   * inside it, including hosts added later.
   */
  agent_forward_credentials?: string[] | null

  /**
   * What to type at a device's own login prompt, for the protocols that have
   * no authentication of their own.
   *
   * Use %USERNAME% and %PASSWORD% rather than literal values: the password is
   * substituted from the credential at connect time, and a literal one here
   * would be stored in the clear.
   */
  logon_steps?: LogonStep[] | null

  serial_baud?: number | null
  serial_data_bits?: number | null
  serial_stop_bits?: number | null
  serial_parity?: string | null
  serial_flow?: string | null
}

export interface LogonStep {
  /** Case-insensitive substring, with "|" alternatives. Empty sends at once. */
  expect: string
  /** Understands %USERNAME%, %PASSWORD% and the escapes \r, \n, \t. */
  send: string
}

export interface ConsoleProfile {
  id: string
  name: string
  telnet_base: number
  ssh_base: number
  first_line: number
  note: string
}

export interface ConsolePlan {
  profile: ConsoleProfile
  protocol: string
  hostname: string
  lines: { line: number; name: string; port: number }[]
  warnings?: string[]
}

export interface Folder {
  id: string
  parent_id: string
  name: string
  defaults: Settings
  sort_order: number
  created_at: string
  updated_at: string
}

export interface SavedSession {
  id: string
  folder_id: string
  name: string
  protocol: 'ssh' | 'telnet' | 'serial'
  hostname: string
  /**
   * The port as saved. Zero means "inherit from the folder", so the editor
   * renders the field blank — the same convention as a blank username.
   */
  port: number
  /**
   * The port this connection will actually dial, after folder inheritance.
   * Always non-zero. This is what a host:port label should show; the raw
   * column would print ":0" for anything taking its folder's default.
   */
  effective_port: number
  username: string
  credential_id: string
  jump_chain: string[]
  settings: Settings
  sort_order: number
  created_at: string
  updated_at: string
  last_used_at?: string
}

export interface Tree {
  folders: Folder[]
  sessions: SavedSession[]
}

export interface ResolvedSession extends SavedSession {
  effective: {
    username: string
    port: number
    credential_id: string
  }
  /** Which folder each inherited value came from, keyed by field name. */
  inherited_from: Record<string, string>
}

export interface LiveTerminal {
  id: string
  session_id?: string
  label: string
  protocol: 'ssh' | 'telnet' | 'serial'
  host: string
  port: number
  /** The serial port's path, for a serial session. */
  device?: string
  /** False for telnet and serial — shown, so nobody has to remember. */
  encrypted: boolean
  username?: string
  created_at: string
  attached: boolean
  closed: boolean
}

export interface KnownHost {
  id: string
  hostname: string
  port: number
  key_type: string
  fingerprint: string
  org_wide: boolean
  created_at: string
}

/** FolderNotEmpty is the 409 returned when a delete would destroy contents. */
export interface FolderNotEmpty {
  folders: number
  sessions: number
}

// --- files ------------------------------------------------------------------

export interface FileEntry {
  name: string
  path: string
  size: number
  mod_time: string
  /** Permission bits in octal, as chmod takes them: "0644". */
  mode: string
  /** The ls-style rendering: "drwxr-xr-x". */
  mode_string: string
  is_dir: boolean
  is_symlink: boolean
  link_target?: string
  /** Whether a symlink resolves to a directory, so it can be opened. */
  target_is_dir?: boolean
  uid: number
  gid: number
  owner?: string
  group?: string
}

export interface Listing {
  path: string
  parent: string
  entries: FileEntry[]
}

export interface FileSession {
  session_id: string
  label: string
  host: string
  port: number
  username?: string
  home: string
  /** Whether the host published /etc/passwd, so chown can take names. */
  owner_names?: boolean
}

export type TransferState = 'running' | 'done' | 'failed' | 'cancelled'

export interface Transfer {
  id: string
  kind: 'copy' | 'delete'
  state: TransferState
  source_session: string
  source_path: string
  dest_session?: string
  dest_path?: string
  name: string
  total_bytes: number
  done_bytes: number
  total_files: number
  done_files: number
  current?: string
  error?: string
  started_at: string
  finished_at?: string
}

/** HostKeyPrompt is the 409 an unrecognised host produces on first contact. */
export interface HostKeyPrompt {
  hostname: string
  port: number
  key_type: string
  fingerprint: string
  previous_fingerprint?: string
  previously_seen?: string
  org_wide?: boolean
}

/**
 * openFileSession starts browsing a host.
 *
 * The host key question is answered in two steps, because a plain HTTP
 * request cannot be interrupted mid-handshake the way the terminal's socket
 * can: the first attempt reports the fingerprint, and `acceptFingerprint`
 * carries the user's answer on a second attempt. The server checks that the
 * accepted fingerprint matches what the host then presents, so answering
 * about one key cannot accept another.
 */
export async function openFileSession(
  sessionId: string,
  acceptFingerprint?: string,
): Promise<FileSession> {
  const query = new URLSearchParams({ session: sessionId })
  if (acceptFingerprint) query.set('accept_host_key', acceptFingerprint)
  return api.post<FileSession>(`/api/files/sessions?${query}`)
}

/** downloadURL is a link the browser's own download manager can follow. */
export function downloadURL(sessionId: string, filePath: string): string {
  const query = new URLSearchParams({ session: sessionId, path: filePath })
  return `/api/files/content?${query}`
}

export interface UploadProgress {
  loaded: number
  total: number
}

/**
 * uploadFile sends one file to a host, reporting progress as it goes.
 *
 * XMLHttpRequest rather than fetch: fetch still cannot report upload
 * progress in any browser, and a large upload with no progress bar is
 * indistinguishable from one that has hung.
 */
export function uploadFile(
  sessionId: string,
  target: string,
  file: Blob,
  options: {
    offset?: number
    onProgress?: (p: UploadProgress) => void
    signal?: AbortSignal
  } = {},
): Promise<{ path: string; bytes: number; size: number }> {
  const offset = options.offset ?? 0
  const query = new URLSearchParams({
    session: sessionId,
    path: target,
    offset: String(offset),
  })

  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    request.open('PUT', `/api/files/content?${query}`)
    request.withCredentials = true

    const token = readCookie(CSRF_COOKIE)
    if (token) request.setRequestHeader(CSRF_HEADER, token)

    request.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) {
        options.onProgress?.({ loaded: event.loaded, total: event.total })
      }
    })

    request.addEventListener('load', () => {
      if (request.status >= 200 && request.status < 300) {
        try {
          resolve(JSON.parse(request.responseText))
        } catch {
          resolve({ path: target, bytes: file.size, size: offset + file.size })
        }
        return
      }

      let message = `The upload failed (${request.status}).`
      let code: ErrorCode = 'internal_error'
      try {
        const parsed = JSON.parse(request.responseText) as {
          error?: { code?: ErrorCode; message?: string }
        }
        if (parsed.error?.message) message = parsed.error.message
        if (parsed.error?.code) code = parsed.error.code
      } catch {
        // A non-JSON body means something upstream intervened.
      }
      reject(new ApiError(request.status, code, message))
    })

    request.addEventListener('error', () =>
      reject(new ApiError(0, 'internal_error', 'The upload could not reach the server.')))
    request.addEventListener('abort', () =>
      reject(new ApiError(0, 'bad_request', 'The upload was cancelled.')))

    options.signal?.addEventListener('abort', () => request.abort())

    request.send(file)
  })
}

// --- import and export -------------------------------------------------------

export type ImportSource = 'bundle' | 'securecrt' | 'ssh_config' | 'putty' | 'csv'

export type ExportFormat =
  | 'bundle' | 'ssh_config' | 'securecrt' | 'putty_reg' | 'json' | 'csv'

export interface PortabilityConfig {
  allow_plaintext_export: boolean
  min_passphrase_length: number
  max_upload_bytes: number
  sources: ImportSource[]
  formats: ExportFormat[]
  formats_carrying_secret: ExportFormat[]
}

export interface ImportConflict {
  kind: string
  name: string
  existing: string
}

export interface ImportPlan {
  counts: {
    folders: number
    sessions: number
    credentials: number
    known_hosts: number
  }
  new_folders: string[]
  new_sessions: string[]
  conflicts: ImportConflict[]
  warnings: string[]
  has_secrets: boolean
}

export interface ImportPreview {
  token: string
  source: ImportSource
  plan: ImportPlan
  warnings: string[]
  notes: string[]
  expires: string
}

export interface ImportResult {
  folders: number
  sessions: number
  credentials: number
  known_hosts: number
  skipped: number
  warnings: string[]
}

/**
 * previewImport uploads a configuration and asks what importing it would do.
 *
 * Nothing is written. The server stages the payload it described and returns
 * a token; committing applies that exact staged copy, so what the user
 * approved is what happens.
 */
export async function previewImport(
  file: File,
  source: ImportSource,
  options: Record<string, string> = {},
): Promise<ImportPreview> {
  const body = new FormData()
  body.append('source', source)
  for (const [name, value] of Object.entries(options)) {
    if (value) body.append(name, value)
  }
  body.append('file', file)

  const headers: Record<string, string> = {}
  const token = readCookie(CSRF_COOKIE)
  if (token) headers[CSRF_HEADER] = token

  const response = await fetch('/api/portability/preview', {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body,
  })

  const text = await response.text()
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new ApiError(response.status, 'internal_error',
      `The server returned an unexpected response (${response.status}).`)
  }

  if (!response.ok) {
    const envelope = parsed as { error?: { code?: ErrorCode; message?: string } }
    throw new ApiError(
      response.status,
      envelope?.error?.code ?? 'internal_error',
      envelope?.error?.message ?? `The upload failed (${response.status}).`,
    )
  }
  return parsed as ImportPreview
}

export interface ExportRequest {
  format: ExportFormat
  include_secrets?: boolean
  include_known_hosts?: boolean
  passphrase?: string
  note?: string
  confirm?: boolean
}

export interface ExportedFile {
  blob: Blob
  filename: string
  /** What the format could not express, reported by the server. */
  warnings: string[]
}

/**
 * exportConnections downloads an export.
 *
 * fetch rather than a link, because the request needs a CSRF header and a
 * body — and because the warnings come back in a header the interface has to
 * show alongside the file.
 */
export async function exportConnections(request: ExportRequest): Promise<ExportedFile> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = readCookie(CSRF_COOKIE)
  if (token) headers[CSRF_HEADER] = token

  const response = await fetch('/api/portability/export', {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: JSON.stringify(request),
  })

  if (!response.ok) {
    const text = await response.text()
    let message = `The export failed (${response.status}).`
    let code: ErrorCode = 'internal_error'
    try {
      const parsed = JSON.parse(text) as { error?: { code?: ErrorCode; message?: string } }
      if (parsed.error?.message) message = parsed.error.message
      if (parsed.error?.code) code = parsed.error.code
    } catch {
      // A non-JSON body means something upstream intervened.
    }
    throw new ApiError(response.status, code, message)
  }

  const disposition = response.headers.get('Content-Disposition') ?? ''
  const match = /filename="([^"]+)"/.exec(disposition)

  const rawWarnings = response.headers.get('X-Export-Warnings') ?? ''
  const warnings = rawWarnings ? rawWarnings.split(' | ').filter(Boolean) : []

  return {
    blob: await response.blob(),
    filename: match?.[1] ?? 'export',
    warnings,
  }
}

/** What this server will and will not do with tunnels. */
export interface TunnelConfig {
  /** Web tunnels need a wildcard domain; without one they are unavailable. */
  web_enabled: boolean
  /** Listening ports on this server, gated by policy.allow_tcp_tunnels. */
  listeners_enabled: boolean
  /** Remote forwards, gated by policy.allow_remote_forwards. */
  remote_enabled: boolean
  domain: string
}

export type TunnelKind = 'web' | 'local' | 'socks' | 'remote'

export interface TunnelHop {
  session_id: string
  name: string
  hostname: string
  port: number
  index: number
  total: number
}

export interface Tunnel {
  id: string
  kind: TunnelKind
  state: 'open' | 'closed' | 'failed'
  session_id: string
  label: string
  via?: TunnelHop[]
  /** Where to point a client. On the device, for a remote forward. */
  listen?: string
  /** The fixed address at the far end of the forwarding. */
  remote?: string
  /** Where a web tunnel is served, on its own origin. */
  url?: string
  connections: number
  active: number
  bytes_up: number
  bytes_down: number
  opened_at: string
  last_used_at: string
  error?: string
}
