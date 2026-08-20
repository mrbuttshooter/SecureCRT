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

/** ApiError carries the server's machine-readable code alongside its message. */
export class ApiError extends Error {
  readonly code: ErrorCode
  readonly status: number
  readonly retryAfterSeconds?: number

  constructor(status: number, code: ErrorCode, message: string, retryAfterSeconds?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfterSeconds = retryAfterSeconds
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
    const envelope = parsed as { error?: { code?: ErrorCode; message?: string; retry_after_seconds?: number } }
    const err = envelope?.error
    throw new ApiError(
      response.status,
      err?.code ?? 'internal_error',
      err?.message ?? `Request failed (${response.status}).`,
      err?.retry_after_seconds,
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
