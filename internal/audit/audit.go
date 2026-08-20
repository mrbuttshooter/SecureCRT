// Package audit records who did what, to which object, and whether it
// succeeded.
//
// The log is append-only. There is no update or delete path in this package
// by design: an audit trail an application can quietly rewrite is not an
// audit trail. Retention is a separate, explicit admin operation that
// archives before pruning.
//
// Nothing written here may contain secret material. Detail fields carry
// identifiers, names, counts and reasons — never a private key, password,
// passphrase, session token or TOTP secret. Recorder enforces this rather
// than trusting callers to remember, because the audit log is precisely the
// place a leaked secret would be preserved forever and shipped to a SIEM.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

// Action names an auditable operation. They are dotted and stable: a SIEM
// rule written against one of these should not break on a refactor.
type Action string

// #nosec G101 -- these are event names written into the audit log, not
// credentials. Static analysis flags identifiers containing "secret" and
// "passphrase" by name; renaming them to appease it would make the log
// harder to read for no security benefit.
const (
	// Authentication.
	ActionLoginSucceeded Action = "auth.login.succeeded"
	ActionLoginFailed    Action = "auth.login.failed"
	ActionLoginThrottled Action = "auth.login.throttled"
	ActionLogout         Action = "auth.logout"
	ActionSessionRevoked Action = "auth.session.revoked"
	ActionSSOSignIn      Action = "auth.sso.signin"
	ActionSSOFailed      Action = "auth.sso.failed"
	ActionSSOProvisioned Action = "auth.sso.provisioned"

	// Multi-factor.
	ActionMFAEnrolled      Action = "auth.mfa.enrolled"
	ActionMFAVerified      Action = "auth.mfa.verified"
	ActionMFAFailed        Action = "auth.mfa.failed"
	ActionMFADisabled      Action = "auth.mfa.disabled"
	ActionRecoveryCodeUsed Action = "auth.mfa.recovery_used"

	// Vault.
	ActionVaultUnlocked          Action = "vault.unlocked"
	ActionVaultUnlockFailed      Action = "vault.unlock.failed"
	ActionVaultLocked            Action = "vault.locked"
	ActionVaultPassphraseSet     Action = "vault.passphrase.set"
	ActionVaultPassphraseChanged Action = "vault.passphrase.changed"
	ActionVaultReset             Action = "vault.reset"

	// Credentials.
	ActionCredentialCreated Action = "credential.created"
	ActionCredentialRead    Action = "credential.read"
	ActionCredentialUpdated Action = "credential.updated"
	ActionCredentialDeleted Action = "credential.deleted"
	ActionCredentialUsed    Action = "credential.used"

	// Import and export. Export is the most security-relevant action in the
	// system, which is why it has its own severity floor below.
	ActionImportPreviewed   Action = "portability.previewed"
	ActionImported          Action = "portability.imported"
	ActionExported          Action = "portability.exported"
	ActionExportedPlaintext Action = "portability.exported_plaintext"

	// Terminals.
	ActionTerminalConnected     Action = "terminal.connected"
	ActionTerminalConnectFailed Action = "terminal.connect.failed"
	ActionTerminalClosed        Action = "terminal.closed"

	// Tunnels. docs/SECURITY.md has claimed since Phase 0 that tunnel
	// creation is audited; from here that is true.
	ActionTunnelOpened   Action = "tunnel.opened"
	ActionTunnelClosed   Action = "tunnel.closed"
	ActionTunnelRefused  Action = "tunnel.refused"
	ActionTunnelListener Action = "tunnel.listener.opened"
	ActionTunnelRemote   Action = "tunnel.remote.opened"
	ActionAgentForwarded Action = "agent.forwarded"

	// ActionConsoleGenerated records a rack's worth of connections being
	// created in one go, which is otherwise forty-eight unremarkable
	// creations that nobody would think to correlate.
	ActionConsoleGenerated Action = "console.generated"

	// ActionSessionRecorded records a transcript being opened. Notice-level:
	// "was this session written down, and where" is a question asked long
	// after the fact, usually by somebody who needs the answer to be findable
	// rather than merely true.
	ActionSessionRecorded Action = "session.recorded"

	// ActionTriggerFired records a rule acting on a session — typing at a
	// device, or ending the connection. Not the ones that merely report:
	// recording every notice would bury the two that changed something.
	ActionTriggerFired Action = "trigger.fired"

	// ActionSnippetSent records a stored command being typed at one or more
	// devices. The snippet's name and how many received it, never the
	// rendered body: a parameter value is whatever somebody typed into a
	// form, and an audit log forwarded to a SIEM is the wrong place to find
	// out what that was.
	ActionSnippetSent Action = "snippet.sent"

	// ActionBroadcastStarted records one keyboard being put onto several
	// terminals. Notice-level: "who typed the same thing at forty production
	// switches, and when" is the first question after a bad afternoon, and it
	// has to outlive ordinary retention.
	ActionBroadcastStarted Action = "terminal.broadcast.started"
	ActionBroadcastStopped Action = "terminal.broadcast.stopped"

	// Files. Reads and writes against a managed host are recorded because
	// "who took a copy of the running configuration, and when" is the first
	// question asked after an incident.
	ActionFileSessionOpened Action = "files.session.opened"
	ActionFileDownloaded    Action = "files.download"
	ActionFileUploaded      Action = "files.upload"
	ActionFileCopied        Action = "files.copy"
	ActionFileDeleted       Action = "files.delete"
	ActionFileTreeDeleted   Action = "files.delete.recursive"
	ActionFileRenamed       Action = "files.rename"
	ActionDirectoryCreated  Action = "files.mkdir"
	ActionFileChmod         Action = "files.chmod"
	ActionFileChown         Action = "files.chown"

	// Administration.
	ActionUserCreated   Action = "admin.user.created"
	ActionUserDisabled  Action = "admin.user.disabled"
	ActionUserEnabled   Action = "admin.user.enabled"
	ActionUserDeleted   Action = "admin.user.deleted"
	ActionRoleChanged   Action = "admin.role.changed"
	ActionPolicyChanged Action = "admin.policy.changed"
)

// Severity grades an event for alerting.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityNotice   Severity = "notice"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Outcome records whether the operation happened.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// minimumSeverity raises the severity of actions that must never be filed
// away as routine, whatever the caller passed.
//
// This exists because severity is easy to get wrong at the call site, and the
// events that matter most in an investigation are exactly the ones a
// distracted author is likeliest to log as "info".
var minimumSeverity = map[Action]Severity{
	ActionExportedPlaintext: SeverityCritical,
	ActionVaultReset:        SeverityCritical,
	ActionUserDeleted:       SeverityWarning,
	ActionRoleChanged:       SeverityWarning,
	ActionPolicyChanged:     SeverityWarning,
	ActionUserDisabled:      SeverityNotice,
	ActionExported:          SeverityNotice,
	ActionRecoveryCodeUsed:  SeverityNotice,
	ActionMFADisabled:       SeverityNotice,
	ActionLoginThrottled:    SeverityNotice,
	ActionSSOFailed:         SeverityNotice,

	// Taking a copy of a file off a managed host, or destroying a tree on
	// one, is exactly the kind of event an investigation starts from. Neither
	// is routine enough to file as "info".
	ActionFileDownloaded:  SeverityNotice,
	ActionFileTreeDeleted: SeverityNotice,

	// A port opened on this server is reachable by whoever can reach the
	// host, account or no account — worth finding in a log without having
	// known to look for it.
	ActionTunnelListener: SeverityNotice,

	// A remote forward is the one tunnel that lets traffic in rather than
	// out. Whoever reaches that port on the device reaches this server's
	// network, so the record of it opening must survive whatever retention
	// an operator sets for ordinary activity.
	ActionTunnelRemote: SeverityNotice,

	// Forwarded keys can be used by the far host for as long as the session
	// lasts. That is the point of agent forwarding and also its whole risk.
	ActionAgentForwarded:   SeverityNotice,
	ActionSessionRecorded:  SeverityNotice,
	ActionBroadcastStarted: SeverityNotice,
}

var severityRank = map[Severity]int{
	SeverityInfo: 0, SeverityNotice: 1, SeverityWarning: 2, SeverityCritical: 3,
}

// forbiddenDetailKeys are rejected outright. A secret reaching the audit log
// would be preserved for the retention period and forwarded to whatever SIEM
// consumes it — the worst possible place for one to land.
var forbiddenDetailKeys = []string{
	"password", "passphrase", "secret", "private_key", "privatekey",
	"token", "credential_secret", "totp_secret", "recovery_code",
	"client_secret", "master_key", "dek", "kek", "api_key", "apikey",
}

// Event is one audit record.
type Event struct {
	ID          string
	OccurredAt  time.Time
	ActorID     string
	ActorEmail  string
	IPAddress   string
	Action      Action
	Severity    Severity
	TargetType  string
	TargetID    string
	TargetLabel string
	Outcome     Outcome
	Detail      map[string]any
}

// Recorder writes audit events.
type Recorder struct {
	db  *store.DB
	log *slog.Logger
	now func() time.Time
}

// NewRecorder builds a Recorder.
func NewRecorder(db *store.DB, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{db: db, log: log, now: time.Now}
}

// Record writes an event.
//
// It never returns an error to the caller's critical path by design — see
// Record's use in handlers. A failure to write audit is logged loudly, but
// must not, for example, prevent a user from logging out.
func (r *Recorder) Record(ctx context.Context, e Event) {
	if err := r.record(ctx, e); err != nil {
		// This is a serious condition: the system is operating without a
		// reliable audit trail. It is logged at error so it pages someone,
		// while the user's operation still completes.
		r.log.Error("failed to write audit event",
			"action", string(e.Action),
			"actor", e.ActorID,
			"error", err)
	}
}

// RecordErr writes an event and returns any failure, for callers that would
// rather abort than proceed unaudited.
func (r *Recorder) RecordErr(ctx context.Context, e Event) error {
	return r.record(ctx, e)
}

func (r *Recorder) record(ctx context.Context, e Event) error {
	if e.Action == "" {
		return fmt.Errorf("audit: event has no action")
	}

	if e.ID == "" {
		e.ID = uuid.Must(uuid.NewV7()).String()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = r.now().UTC()
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.Outcome == "" {
		e.Outcome = OutcomeSuccess
	}

	// Raise severity to the floor for this action, never lower it.
	if floor, ok := minimumSeverity[e.Action]; ok {
		if severityRank[e.Severity] < severityRank[floor] {
			e.Severity = floor
		}
	}

	detail, err := encodeDetail(e.Detail)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO audit_events
			(id, occurred_at, actor_id, actor_email, ip_address,
			 action, severity, target_type, target_id, target_label, outcome, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.OccurredAt.UTC().Format(time.RFC3339Nano),
		nullable(e.ActorID), e.ActorEmail, e.IPAddress,
		string(e.Action), string(e.Severity),
		e.TargetType, e.TargetID, e.TargetLabel,
		string(e.Outcome), detail,
	)
	if err != nil {
		return fmt.Errorf("audit: write event: %w", err)
	}
	return nil
}

// encodeDetail serialises the detail map, refusing anything that looks like a
// secret.
func encodeDetail(detail map[string]any) (string, error) {
	if len(detail) == 0 {
		return "{}", nil
	}

	for key := range detail {
		lower := strings.ToLower(key)
		for _, forbidden := range forbiddenDetailKeys {
			if strings.Contains(lower, forbidden) {
				return "", fmt.Errorf(
					"audit: detail key %q looks like secret material; "+
						"audit records are retained and forwarded to log collectors, "+
						"so they must never carry secrets", key)
			}
		}
	}

	encoded, err := json.Marshal(detail)
	if err != nil {
		return "", fmt.Errorf("audit: encode detail: %w", err)
	}
	return string(encoded), nil
}

// nullable maps an empty string to NULL, so audit rows for unauthenticated
// events do not carry a meaningless empty actor.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Query filters an audit search.
type Query struct {
	ActorID string
	Action  Action
	Since   time.Time
	Until   time.Time
	Limit   int
}

// List returns matching events, newest first.
func (r *Recorder) List(ctx context.Context, q Query) ([]Event, error) {
	sql := `SELECT id, occurred_at, actor_id, actor_email, ip_address,
	               action, severity, target_type, target_id, target_label, outcome, detail
	        FROM audit_events WHERE 1=1`
	var args []any

	if q.ActorID != "" {
		sql += ` AND actor_id = ?`
		args = append(args, q.ActorID)
	}
	if q.Action != "" {
		sql += ` AND action = ?`
		args = append(args, string(q.Action))
	}
	if !q.Since.IsZero() {
		sql += ` AND occurred_at >= ?`
		args = append(args, q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		sql += ` AND occurred_at <= ?`
		args = append(args, q.Until.UTC().Format(time.RFC3339Nano))
	}

	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	sql += ` ORDER BY occurred_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := r.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Event
	for rows.Next() {
		var (
			e          Event
			occurred   string
			actorID    *string
			action     string
			severity   string
			outcome    string
			detailJSON string
		)
		if err := rows.Scan(&e.ID, &occurred, &actorID, &e.ActorEmail, &e.IPAddress,
			&action, &severity, &e.TargetType, &e.TargetID, &e.TargetLabel,
			&outcome, &detailJSON); err != nil {
			return nil, fmt.Errorf("audit: scan event: %w", err)
		}

		if e.OccurredAt, err = time.Parse(time.RFC3339Nano, occurred); err != nil {
			return nil, fmt.Errorf("audit: unparseable timestamp %q: %w", occurred, err)
		}
		if actorID != nil {
			e.ActorID = *actorID
		}
		e.Action = Action(action)
		e.Severity = Severity(severity)
		e.Outcome = Outcome(outcome)

		if detailJSON != "" && detailJSON != "{}" {
			if err := json.Unmarshal([]byte(detailJSON), &e.Detail); err != nil {
				return nil, fmt.Errorf("audit: decode detail: %w", err)
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate events: %w", err)
	}
	return out, nil
}
