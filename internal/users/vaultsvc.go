package users

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// SSOUnlockMode decides how a single-sign-on user's vault is protected.
//
// This is the most consequential setting in the system, so it is a named type
// with exactly two values rather than a loose boolean.
type SSOUnlockMode string

const (
	// SSOUnlockPassphrase asks an SSO user for a separate vault passphrase
	// after signing in with Microsoft. The server cannot decrypt their
	// credentials without it, so a stolen database — even with the master
	// key — yields nothing.
	//
	// The cost is one extra prompt per working day, since the unlocked key is
	// cached for the configured TTL.
	SSOUnlockPassphrase SSOUnlockMode = "passphrase"

	// SSOUnlockServerManaged wraps an SSO user's key under the server master
	// key, so signing in with Microsoft is enough to open everything.
	//
	// This is what most commercial web-SSH products do, and it is a
	// defensible choice — but it discards the property that a stolen database
	// plus master key is useless. Whoever owns security should make this call
	// knowingly rather than inheriting it from a default.
	SSOUnlockServerManaged SSOUnlockMode = "server_managed"
)

// Validate rejects an unrecognised mode.
func (m SSOUnlockMode) Validate() error {
	switch m {
	case SSOUnlockPassphrase, SSOUnlockServerManaged:
		return nil
	default:
		return fmt.Errorf("users: sso_unlock_mode %q must be %q or %q",
			m, SSOUnlockPassphrase, SSOUnlockServerManaged)
	}
}

// WeakensSecurity reports whether this mode gives up the stolen-database
// guarantee. Used to emit a startup warning and to mark affected credentials.
func (m SSOUnlockMode) WeakensSecurity() bool {
	return m == SSOUnlockServerManaged
}

// Vault errors.
var (
	// ErrVaultLocked means the caller has no unwrapped key for this session.
	ErrVaultLocked = errors.New("users: vault is locked")

	// ErrWrongPassphrase means the supplied passphrase did not open the
	// vault. Indistinguishable from a corrupted record, deliberately.
	ErrWrongPassphrase = vault.ErrWrongPassphrase

	// ErrVaultAlreadySetUp means enrolment was attempted on a vault that
	// already exists. Overwriting it would orphan every credential.
	ErrVaultAlreadySetUp = errors.New("users: this account already has a vault")
)

// vaultCacheKey scopes a cached key to both its owner and its session.
//
// The session ID alone would be enough to look a key up, but not to purge one
// user's keys without touching anyone else's — and purging by user is needed
// whenever an account is disabled, its passphrase changes, or its vault is
// reset. Encoding the owner in the key makes that a prefix match instead of a
// second index.
func vaultCacheKey(userID, sessionID string) string {
	return userID + "\x00" + sessionID
}

// vaultCacheKeyIsOwnedBy reports whether a cache key belongs to a user.
func vaultCacheKeyIsOwnedBy(key, userID string) bool {
	return strings.HasPrefix(key, userID+"\x00")
}

// VaultService enrols and opens user vaults.
type VaultService struct {
	users     *Store
	cache     *vault.Cache
	master    vault.Key
	kdf       func() (vault.KDFParams, error)
	ssoUnlock SSOUnlockMode
}

// VaultServiceConfig configures a VaultService.
type VaultServiceConfig struct {
	// Argon2 costs applied to newly enrolled and re-keyed vaults. Existing
	// vaults keep the parameters they were created with.
	Argon2Time     uint32
	Argon2MemoryKB uint32
	Argon2Threads  uint8

	SSOUnlockMode SSOUnlockMode
}

// NewVaultService builds a VaultService.
func NewVaultService(us *Store, cache *vault.Cache, master vault.Key, cfg VaultServiceConfig) (*VaultService, error) {
	if err := cfg.SSOUnlockMode.Validate(); err != nil {
		return nil, err
	}
	// Fail here rather than at first enrolment: a bad cost setting should
	// stop the server starting, not surprise the first user to sign up.
	if _, err := vault.NewKDFParams(cfg.Argon2Time, cfg.Argon2MemoryKB, cfg.Argon2Threads); err != nil {
		return nil, err
	}

	return &VaultService{
		users:  us,
		cache:  cache,
		master: master,
		kdf: func() (vault.KDFParams, error) {
			return vault.NewKDFParams(cfg.Argon2Time, cfg.Argon2MemoryKB, cfg.Argon2Threads)
		},
		ssoUnlock: cfg.SSOUnlockMode,
	}, nil
}

// SSOUnlockMode reports the configured mode.
func (v *VaultService) SSOUnlockMode() SSOUnlockMode { return v.ssoUnlock }

// RequiresPassphrase reports whether this user must supply a passphrase to
// open their vault, which is what the interface asks in order to decide
// whether to prompt after an SSO sign-in.
func (v *VaultService) RequiresPassphrase(u User) bool {
	if u.IsSSO() && v.ssoUnlock == SSOUnlockServerManaged {
		return false
	}
	return true
}

// Enrol creates a user's vault and caches the key for the session.
//
// kind must match how the account signs in: an SSO account cannot use
// UnlockDerived, because there is no local password to derive from.
func (v *VaultService) Enrol(ctx context.Context, u User, sessionID, passphrase string) (UnlockKind, error) {
	if u.HasVault() {
		return "", ErrVaultAlreadySetUp
	}

	kind := v.kindFor(u)

	if kind == UnlockServer {
		return kind, v.enrolServerManaged(ctx, u, sessionID)
	}

	if passphrase == "" {
		return "", errors.New("users: a vault passphrase is required")
	}

	params, err := v.kdf()
	if err != nil {
		return "", err
	}

	dek, wrapped, err := vault.NewUserKey(u.ID, []byte(passphrase), params)
	if err != nil {
		return "", err
	}

	if err := v.users.SetVault(ctx, u.ID, kind, wrapped); err != nil {
		dek.Zero()
		return "", err
	}

	// The cache takes ownership of dek; it must not be zeroed here.
	v.cache.Put(vaultCacheKey(u.ID, sessionID), dek)
	return kind, nil
}

// enrolServerManaged wraps a fresh key under the master key.
func (v *VaultService) enrolServerManaged(ctx context.Context, u User, sessionID string) error {
	dek, err := vault.NewKey()
	if err != nil {
		return err
	}

	env, err := vault.SealKeyUnder(v.master, vault.MasterAAD(u.ID, "user-dek"), dek)
	if err != nil {
		dek.Zero()
		return err
	}

	// KDF params are unused in this mode, but a placeholder keeps the stored
	// shape uniform so readers do not need a special case.
	params, err := v.kdf()
	if err != nil {
		dek.Zero()
		return err
	}

	if err := v.users.SetVault(ctx, u.ID, UnlockServer, vault.WrappedKey{KDF: params, Envelope: env}); err != nil {
		dek.Zero()
		return err
	}

	v.cache.Put(vaultCacheKey(u.ID, sessionID), dek)
	return nil
}

// kindFor decides how a given account's vault should be wrapped.
func (v *VaultService) kindFor(u User) UnlockKind {
	if u.IsSSO() {
		if v.ssoUnlock == SSOUnlockServerManaged {
			return UnlockServer
		}
		// An SSO user has no password the server ever sees, so their vault
		// must be protected by something they type separately.
		return UnlockSeparate
	}
	if u.CanSignInLocally() {
		return UnlockDerived
	}
	return UnlockSeparate
}

// Unlock opens a user's vault and caches the key against the session.
func (v *VaultService) Unlock(ctx context.Context, u User, sessionID, passphrase string) error {
	if !u.HasVault() {
		return ErrVaultNotSetUp
	}

	if u.UnlockKind == UnlockServer {
		dek, err := vault.OpenKeyFrom(v.master, vault.MasterAAD(u.ID, "user-dek"), u.WrappedDEK.Envelope)
		if err != nil {
			return fmt.Errorf("users: unwrap server-managed vault: %w", err)
		}
		v.cache.Put(vaultCacheKey(u.ID, sessionID), dek)
		return nil
	}

	if passphrase == "" {
		return ErrWrongPassphrase
	}

	dek, err := vault.UnwrapUserKey(u.ID, []byte(passphrase), *u.WrappedDEK)
	if err != nil {
		return err
	}

	v.cache.Put(vaultCacheKey(u.ID, sessionID), dek)
	return nil
}

// Key returns the unwrapped key for a user's session.
func (v *VaultService) Key(userID, sessionID string) (vault.Key, error) {
	key, err := v.cache.Get(vaultCacheKey(userID, sessionID))
	if err != nil {
		return nil, ErrVaultLocked
	}
	return key, nil
}

// Lock forgets one session's key, zeroing it. Called on logout.
func (v *VaultService) Lock(userID, sessionID string) {
	v.cache.Forget(vaultCacheKey(userID, sessionID))
}

// LockAllForUser zeroes every cached key belonging to one user, across all
// their sessions, and reports how many were cleared.
//
// Needed whenever an account is disabled, its passphrase changes, or its
// vault is reset: revoking the session rows closes the front door, but the
// decrypted key would otherwise sit in memory until its TTL expired.
func (v *VaultService) LockAllForUser(userID string) int {
	return v.cache.ForgetFunc(func(key string) bool {
		return vaultCacheKeyIsOwnedBy(key, userID)
	})
}

// ChangePassphrase re-wraps the existing key under a new passphrase.
//
// The key itself is unchanged, so no credential is re-encrypted: this stays a
// single small row update whether the user has three saved sessions or three
// thousand. It also upgrades the Argon2id cost to whatever is currently
// configured.
func (v *VaultService) ChangePassphrase(ctx context.Context, u User, sessionID, current, next string) error {
	if !u.HasVault() {
		return ErrVaultNotSetUp
	}
	if next == "" {
		return errors.New("users: the new passphrase must not be empty")
	}
	if u.UnlockKind == UnlockServer {
		return errors.New("users: this vault is server-managed and has no passphrase to change")
	}

	// Verified against the stored record rather than the cached key, so a
	// hijacked session cannot change the passphrase without knowing the
	// current one.
	dek, err := vault.UnwrapUserKey(u.ID, []byte(current), *u.WrappedDEK)
	if err != nil {
		return err
	}
	defer dek.Zero()

	params, err := v.kdf()
	if err != nil {
		return err
	}

	rewrapped, err := vault.RewrapUserKey(u.ID, dek, []byte(next), params)
	if err != nil {
		return err
	}
	if err := v.users.SetVault(ctx, u.ID, u.UnlockKind, rewrapped); err != nil {
		return err
	}

	// Re-cache a fresh copy so the caller's session keeps working; the local
	// copy above is zeroed by the deferred call.
	fresh, err := vault.UnwrapUserKey(u.ID, []byte(next), rewrapped)
	if err != nil {
		return err
	}
	v.cache.Put(vaultCacheKey(u.ID, sessionID), fresh)
	return nil
}

// Reset discards a user's vault and everything it protected.
//
// Irreversible: the credentials cannot be recovered, because the key that
// opened them is gone. This is the honest consequence of a design where the
// server cannot decrypt on its own, and the reason the interface must warn
// before offering it.
func (v *VaultService) Reset(ctx context.Context, u User) error {
	if err := v.users.ResetVault(ctx, u.ID); err != nil {
		return err
	}
	// Purge this user's cached keys across every session, so a still-open tab
	// cannot keep using the vault that was just destroyed. Scoped to the one
	// user: an earlier version of this cleared the whole cache, which would
	// have logged out everybody else at the same time.
	v.LockAllForUser(u.ID)
	return nil
}
