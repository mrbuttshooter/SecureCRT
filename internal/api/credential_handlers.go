package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
)

// credentialView is what the API returns for a credential.
//
// Built by hand rather than serialising the domain type, so adding a field to
// the internal struct can never silently start publishing it.
func credentialView(c credentials.Credential) map[string]any {
	view := map[string]any{
		"id":                c.ID,
		"name":              c.Name,
		"kind":              string(c.Kind),
		"username":          c.Username,
		"public_key":        c.PublicKey,
		"fingerprint":       c.Fingerprint,
		"key_type":          c.KeyType,
		"server_unlockable": c.ServerUnlockable,
		"created_at":        c.CreatedAt.Format(time.RFC3339),
		"updated_at":        c.UpdatedAt.Format(time.RFC3339),
	}
	if c.LastUsedAt != nil {
		view["last_used_at"] = c.LastUsedAt.Format(time.RFC3339)
	}
	return view
}

// handleListCredentials returns the user's credentials.
//
// Needs no vault key: the fields shown here are stored in the clear, so the
// list renders on a locked vault instead of demanding a passphrase to see
// what you own.
func (a *API) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	list, err := a.credentials.List(r.Context(), u.ID, false)
	if err != nil {
		writeInternal(w, a.log, "listing credentials", err)
		return
	}

	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, credentialView(c))
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"credentials": out})
}

// credentialID extracts the ID from a path, rejecting anything with a slash so
// a nested path cannot be read as an ID.
func credentialID(path string) string {
	id := strings.TrimPrefix(path, "/api/credentials/")
	if id == "" || strings.Contains(id, "/") {
		return ""
	}
	return id
}

// handleGetCredential returns one credential's metadata.
//
// Deliberately never its secret. Revealing private key material is not part
// of this phase: the terminal in Phase 2 uses the key server-side without it
// ever reaching the browser, which is the whole point of storing it here.
func (a *API) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := credentialID(r.URL.Path)
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No credential was specified.")
		return
	}

	c, err := a.credentials.Get(r.Context(), u.ID, id)
	if err != nil {
		a.writeCredentialError(w, err, "loading credential")
		return
	}
	writeJSON(w, a.log, http.StatusOK, credentialView(c))
}

type createCredentialRequest struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
	Extra    string `json:"extra"`
}

// handleCreateCredential stores a password, passphrase or enable secret.
func (a *API) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	var req createCredentialRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	kind := credentials.Kind(req.Kind)
	if err := kind.Validate(); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That credential type is not recognised.")
		return
	}
	// Private keys go through the import endpoint, which parses and validates
	// them and derives the public half. Accepting one here would store an
	// unvalidated blob with no fingerprint.
	if kind == credentials.KindSSHKey {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"Use the import endpoint for SSH keys, so the key can be validated and its fingerprint recorded.")
		return
	}
	if req.Secret == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "A secret value is required.")
		return
	}

	c, err := a.credentials.Create(r.Context(), key, credentials.CreateParams{
		OwnerID:  u.ID,
		Name:     req.Name,
		Kind:     kind,
		Username: req.Username,
		Secret:   req.Secret,
		Extra:    req.Extra,
	})
	if err != nil {
		a.writeCredentialError(w, err, "creating credential")
		return
	}

	a.auditCredential(r, audit.ActionCredentialCreated, c)
	writeJSON(w, a.log, http.StatusCreated, credentialView(c))
}

type generateKeyRequest struct {
	Name     string `json:"name"`
	KeyType  string `json:"key_type"`
	Username string `json:"username"`
	Comment  string `json:"comment"`
}

// handleGenerateKey creates a keypair and stores the private half.
//
// The private key is generated on the server and never sent to the browser.
// The response carries the public key, which is what the user needs to
// deploy, and the fingerprint, which is what they need to verify it.
func (a *API) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	var req generateKeyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	keyType := credentials.KeyType(req.KeyType)
	if req.KeyType == "" {
		keyType = credentials.KeyEd25519
	}
	if err := keyType.Validate(); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	comment := req.Comment
	if comment == "" {
		// A default label beats an unlabelled entry: an authorized_keys file
		// full of anonymous keys is one nobody dares prune.
		comment = u.Email
	}

	generated, err := credentials.GenerateKey(keyType, comment)
	if err != nil {
		writeInternal(w, a.log, "generating key", err)
		return
	}

	c, err := a.credentials.Create(r.Context(), key, credentials.CreateParams{
		OwnerID:     u.ID,
		Name:        req.Name,
		Kind:        credentials.KindSSHKey,
		Username:    req.Username,
		Secret:      generated.PrivateKeyPEM,
		PublicKey:   generated.PublicKey,
		Fingerprint: generated.Fingerprint,
		KeyType:     string(generated.KeyType),
	})
	if err != nil {
		a.writeCredentialError(w, err, "storing generated key")
		return
	}

	a.auditCredential(r, audit.ActionCredentialCreated, c)

	view := credentialView(c)
	view["notice"] = "The private key is stored encrypted and never leaves the server. " +
		"Add the public key below to the hosts you want to reach."
	writeJSON(w, a.log, http.StatusCreated, view)
}

type importKeyRequest struct {
	Name       string `json:"name"`
	Username   string `json:"username"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase"`
}

// handleImportKey stores an existing private key.
func (a *API) handleImportKey(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	var req importKeyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.PrivateKey) == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "A private key is required.")
		return
	}

	imported, err := credentials.ImportKey([]byte(req.PrivateKey), req.Passphrase)
	switch {
	case errors.Is(err, credentials.ErrKeyEncrypted):
		// A distinct code so the client can prompt for the passphrase rather
		// than showing a generic failure.
		writeError(w, a.log, http.StatusBadRequest, "key_encrypted",
			"This key is protected by a passphrase. Supply it to import the key.")
		return
	case errors.Is(err, credentials.ErrKeyPassphrase):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That passphrase did not decrypt the key.")
		return
	case errors.Is(err, credentials.ErrNotAPrivateKey):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That does not look like a private key. Paste the whole file, including its BEGIN and END lines.")
		return
	case err != nil:
		writeInternal(w, a.log, "importing key", err)
		return
	}

	c, err := a.credentials.Create(r.Context(), key, credentials.CreateParams{
		OwnerID:     u.ID,
		Name:        req.Name,
		Kind:        credentials.KindSSHKey,
		Username:    req.Username,
		Secret:      imported.PrivateKeyPEM,
		PublicKey:   imported.PublicKey,
		Fingerprint: imported.Fingerprint,
		KeyType:     string(imported.KeyType),
	})
	if err != nil {
		a.writeCredentialError(w, err, "storing imported key")
		return
	}

	a.auditCredential(r, audit.ActionCredentialCreated, c)

	view := credentialView(c)
	if imported.WasEncrypted {
		view["notice"] = "This key's own passphrase has been removed. It is now protected by your vault, " +
			"so you will not be asked for that passphrase again."
	}
	writeJSON(w, a.log, http.StatusCreated, view)
}

type updateCredentialRequest struct {
	Name     *string `json:"name"`
	Username *string `json:"username"`
}

// handleUpdateCredential renames a credential or changes its username.
func (a *API) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := credentialID(r.URL.Path)
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No credential was specified.")
		return
	}

	var req updateCredentialRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	c, err := a.credentials.Update(r.Context(), u.ID, id, credentials.UpdateParams{
		Name: req.Name, Username: req.Username,
	})
	if err != nil {
		a.writeCredentialError(w, err, "updating credential")
		return
	}

	a.auditCredential(r, audit.ActionCredentialUpdated, c)
	writeJSON(w, a.log, http.StatusOK, credentialView(c))
}

// handleDeleteCredential removes a credential.
func (a *API) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := credentialID(r.URL.Path)
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No credential was specified.")
		return
	}

	// Read it first so the audit record can name what was deleted. Afterwards
	// there is nothing left to name, which makes the log far less useful.
	existing, err := a.credentials.Get(r.Context(), u.ID, id)
	if err != nil {
		a.writeCredentialError(w, err, "loading credential")
		return
	}

	if err := a.credentials.Delete(r.Context(), u.ID, id); err != nil {
		a.writeCredentialError(w, err, "deleting credential")
		return
	}

	a.auditCredential(r, audit.ActionCredentialDeleted, existing)
	writeJSON(w, a.log, http.StatusOK, map[string]any{"deleted": true})
}

// writeCredentialError maps store errors to responses.
func (a *API) writeCredentialError(w http.ResponseWriter, err error, context string) {
	switch {
	case errors.Is(err, credentials.ErrNotFound):
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such credential.")
	case errors.Is(err, credentials.ErrNoSecret):
		writeError(w, a.log, http.StatusConflict, CodeConflict, "That credential holds no secret.")
	default:
		// Validation failures carry a message written for the user; anything
		// else is a fault and must not be echoed back.
		if isValidationError(err) {
			writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, userFacing(err))
			return
		}
		writeInternal(w, a.log, context, err)
	}
}

// isValidationError reports whether an error came from input validation.
//
// Matching on the message prefix is blunt, but the alternative — a typed
// error for every field rule — would be more machinery than the rules
// deserve, and getting it wrong only costs a less specific message.
func isValidationError(err error) bool {
	msg := err.Error()
	for _, prefix := range []string{
		"credentials: a name is required",
		"credentials: an owner is required",
		"credentials: unknown kind",
		"credentials: unsupported key type",
	} {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}

// userFacing strips the package prefix from a validation message.
func userFacing(err error) string {
	msg := err.Error()
	if _, rest, found := strings.Cut(msg, ": "); found {
		return strings.ToUpper(rest[:1]) + rest[1:] + "."
	}
	return msg
}

// auditCredential records a credential operation.
func (a *API) auditCredential(r *http.Request, action audit.Action, c credentials.Credential) {
	u, _ := UserFrom(r.Context())

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action:      action,
		TargetType:  "credential",
		TargetID:    c.ID,
		TargetLabel: c.Name,
		Detail: map[string]any{
			"credential_kind": string(c.Kind),
			"key_type":        c.KeyType,
			"fingerprint":     c.Fingerprint,
		},
	})
}
