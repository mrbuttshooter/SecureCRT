package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/logging"
	"github.com/mrbuttshooter/securecrt/internal/portability"
	"github.com/mrbuttshooter/securecrt/internal/server"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Bulk migration from the command line.
//
// The browser moves one person's connections at a time and only that person
// can drive it. Migrating a team of eighty off SecureCRT that way means eighty
// people each remembering to do it on a particular Tuesday. These commands run
// the same conversion against the database, so it can be a loop in a script.
//
// Import writes nothing without -commit. The default is to print the plan and
// stop, which is the same promise the interface makes: nothing is written
// until somebody has seen what would happen.

const importUsage = `bkd import — bring connections in from another client

Usage:
  bkd import -user <email> -source <source> -file <path> [flags]

Sources:
  securecrt    a zip of a SecureCRT configuration folder, passwords included
  ssh_config   a zip of a .ssh directory
  putty        a .reg export, or a zip of a .putty directory with its .ppk keys
  csv          a spreadsheet of hosts
  bundle       a .bkbundle exported from bkd

Nothing is written without -commit: without it this prints what would happen
and exits, so a migration can be checked before it lands on somebody's tree.

The account's vault passphrase is read from BKD_VAULT_PASSPHRASE, or prompted
for. The vault must already exist — the user has to have signed in once.
`

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	cfgPath := configFlag(fs)

	email := fs.String("user", "", "the account to import into (required)")
	source := fs.String("source", "", "securecrt | ssh_config | putty | csv | bundle (required)")
	file := fs.String("file", "", "the file to read (required)")
	commit := fs.Bool("commit", false, "actually write; without this the plan is printed and nothing changes")

	onConflict := fs.String("on-conflict", "skip", "skip | rename | replace, for names that already exist")
	intoFolder := fs.String("into-folder", "", "put everything under this existing folder ID")
	skipKnownHosts := fs.Bool("skip-known-hosts", false, "leave accepted host keys behind")
	noSecrets := fs.Bool("no-secrets", false,
		"import connections and folders only, leaving keys and passwords behind; "+
			"this is what works for an account that has not signed in yet")

	bundlePassphrase := fs.String("bundle-passphrase", "", "passphrase for a .bkbundle")
	configPassphrase := fs.String("config-passphrase", "", "SecureCRT configuration passphrase, if one was set")
	keyPassphrase := fs.String("key-passphrase", "", "passphrase for encrypted PuTTY .ppk files")
	skipPasswords := fs.Bool("skip-passwords", false, "leave SecureCRT's saved passwords behind")
	importKeys := fs.Bool("import-keys", true, "import the private keys an ssh config names")
	importKnownHosts := fs.Bool("import-known-hosts", true, "import known_hosts from an ssh directory")
	folder := fs.String("folder", "", "folder name for a CSV or PuTTY import")

	fs.Usage = func() { fmt.Fprint(os.Stderr, importUsage, "\nFlags:\n"); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case *email == "":
		return errors.New("-user is required")
	case *source == "":
		return errors.New("-source is required")
	case *file == "":
		return errors.New("-file is required")
	}

	conflict, err := parseConflict(*onConflict)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *file, err)
	}

	imported, err := portability.ReadUpload(
		portability.Source(*source), filepath.Base(*file), data,
		portability.UploadOptions{
			BundlePassphrase: *bundlePassphrase,
			ConfigPassphrase: *configPassphrase,
			SkipPasswords:    *skipPasswords,
			KeyPassphrase:    *keyPassphrase,
			ImportKeys:       *importKeys,
			ImportKnownHosts: *importKnownHosts,
			FolderName:       *folder,
		})
	if err != nil {
		return err
	}

	if *noSecrets {
		imported.Payload.Credentials = nil
		for i := range imported.Payload.Sessions {
			imported.Payload.Sessions[i].CredentialID = ""
		}
	}

	ctx, cancel, mig, err := migratorContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer mig.Close()

	u, err := mig.Find(ctx, *email)
	if err != nil {
		return err
	}

	// The account is resolved before the passphrase is asked for, so an
	// account that has never signed in is reported as such rather than as a
	// prompt for a secret that does not exist. And a payload with nothing to
	// encrypt needs no vault at all, which is what makes a bulk pre-load
	// possible on day one.
	var key vault.Key
	if len(imported.Payload.Credentials) > 0 {
		passphrase, err := vaultPassphrase(*email, u.HasVault())
		if err != nil {
			return err
		}
		if key, err = mig.Unlock(ctx, u, passphrase); err != nil {
			return err
		}
	}

	opts := portability.ImportOptions{
		IntoFolder:     *intoFolder,
		OnConflict:     conflict,
		SkipKnownHosts: *skipKnownHosts,
	}

	plan, err := mig.Preview(ctx, u, imported.Payload, opts)
	if err != nil {
		return err
	}

	printPlan(*file, imported, plan, u.Email)

	if !*commit {
		fmt.Println("\nNothing was written. Run again with -commit to apply this.")
		return nil
	}

	result, err := mig.Import(ctx, u, key, imported.Payload, opts, imported.Source)
	if err != nil {
		return err
	}

	fmt.Printf("\nImported into %s:\n", u.Email)
	fmt.Printf("  folders:     %d\n", result.Folders)
	fmt.Printf("  connections: %d\n", result.Sessions)
	fmt.Printf("  credentials: %d\n", result.Credentials)
	fmt.Printf("  host keys:   %d\n", result.KnownHosts)
	if result.Skipped > 0 {
		fmt.Printf("  skipped:     %d (already present)\n", result.Skipped)
	}
	for _, warning := range result.Warnings {
		fmt.Printf("  ! %s\n", warning)
	}
	return nil
}

// printPlan shows what an import would do, before it does it.
func printPlan(file string, imported portability.Import, plan portability.Plan, email string) {
	fmt.Printf("%s → %s (read as %s)\n\n", filepath.Base(file), email, imported.Source)

	fmt.Printf("Would create:\n")
	fmt.Printf("  folders:     %d\n", plan.Counts.Folders)
	fmt.Printf("  connections: %d\n", plan.Counts.Sessions)
	fmt.Printf("  credentials: %d\n", plan.Counts.Credentials)
	fmt.Printf("  host keys:   %d\n", plan.Counts.KnownHosts)

	if plan.HasSecrets {
		fmt.Println("\nThis carries key material: passwords or private keys came across.")
	}

	if len(plan.Conflicts) > 0 {
		fmt.Printf("\n%d name%s already in use:\n", len(plan.Conflicts), plural(len(plan.Conflicts)))
		for _, conflict := range firstN(plan.Conflicts, 10) {
			fmt.Printf("  %s %q\n", conflict.Kind, conflict.Name)
		}
		if len(plan.Conflicts) > 10 {
			fmt.Printf("  ... and %d more\n", len(plan.Conflicts)-10)
		}
	}

	for _, note := range imported.Notes {
		fmt.Printf("\n  %s\n", note)
	}
	for _, warning := range append(imported.Warnings, plan.Warnings...) {
		fmt.Printf("\n  ! %s\n", warning)
	}
}

const exportUsage = `bkd export — write an account's connections to a file

Usage:
  bkd export -user <email> -format <format> -out <path> [flags]

Formats:
  bundle       encrypted, full fidelity, the one to use for a migration
  ssh_config   an OpenSSH client config
  securecrt    SecureCRT .ini sessions
  putty        a PuTTY .reg
  json         everything, readable
  csv          a spreadsheet

Only "bundle" is encrypted. Every other format writes to a file that nothing
protects, so with -include-secrets they need policy.allow_plaintext_export
on and an explicit -confirm, and the export is recorded as a critical event.
`

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	cfgPath := configFlag(fs)

	email := fs.String("user", "", "the account to export (required)")
	format := fs.String("format", "bundle", "bundle | ssh_config | securecrt | putty | json | csv")
	out := fs.String("out", "", "file to write, or - for standard output (required)")

	passphrase := fs.String("passphrase", "", "passphrase for the bundle; read from BKD_BUNDLE_PASSPHRASE if unset")
	note := fs.String("note", "", "a note stored in the bundle's readable header")
	includeSecrets := fs.Bool("include-secrets", true, "carry private keys and passwords")
	includeKnownHosts := fs.Bool("include-known-hosts", true, "carry accepted host keys")
	confirm := fs.Bool("confirm", false, "acknowledge that a plaintext format is not encrypted")

	fs.Usage = func() { fmt.Fprint(os.Stderr, exportUsage, "\nFlags:\n"); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *email == "" {
		return errors.New("-user is required")
	}
	if *out == "" {
		return errors.New("-out is required (use - for standard output)")
	}

	chosen := portability.Format(*format)

	var err error
	bundleSecret := *passphrase
	if chosen == portability.FormatBundle && bundleSecret == "" {
		if fromEnv := os.Getenv("BKD_BUNDLE_PASSPHRASE"); fromEnv != "" {
			bundleSecret = fromEnv
		} else if bundleSecret, err = readPasswordTwice("Passphrase for the bundle"); err != nil {
			return err
		}
	}

	ctx, cancel, mig, err := migratorContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer mig.Close()

	u, err := mig.Find(ctx, *email)
	if err != nil {
		return err
	}

	var key vault.Key
	if *includeSecrets {
		passphrase, err := vaultPassphrase(*email, u.HasVault())
		if err != nil {
			return err
		}
		if key, err = mig.Unlock(ctx, u, passphrase); err != nil {
			return err
		}
	}

	file, closeFile, err := openExportTarget(*out)
	if err != nil {
		return err
	}
	defer closeFile()

	warnings, err := mig.Export(ctx, u, key, server.ExportRequest{
		Format:            chosen,
		BundlePassphrase:  bundleSecret,
		Note:              *note,
		IncludeSecrets:    *includeSecrets,
		IncludeKnownHosts: *includeKnownHosts,
		Confirm:           *confirm,
	}, file)
	if err != nil {
		return err
	}

	// Progress goes to stderr so "-out -" stays pipeable.
	if *out != "-" {
		fmt.Fprintf(os.Stderr, "Wrote %s\n", *out)
	}
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "  ! %s\n", warning)
	}
	return nil
}

// openExportTarget opens the destination, refusing to overwrite silently.
//
// An export is the thing somebody has just spent an hour preparing. Clobbering
// last week's bundle because two commands shared a filename is the kind of
// data loss that is entirely avoidable.
func openExportTarget(path string) (*os.File, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}

	// #nosec G304 -- the destination is the operator's own -out flag; choosing
	// where their export lands is the entire purpose of it.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, nil, fmt.Errorf("%s already exists; move it aside or choose another name", path)
	}
	if err != nil {
		return nil, nil, err
	}

	return file, func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "bkd: closing %s: %v\n", path, err)
		}
	}, nil
}

func migratorContext(cfgPath string) (context.Context, context.CancelFunc, *server.Migrator, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}
	log := logging.Setup("warn", "text", os.Stderr)

	ctx, cancel := signalContext()
	mig, err := server.NewMigrator(ctx, cfg, log)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return ctx, cancel, mig, nil
}

// vaultPassphrase reads the account's vault passphrase.
//
// The environment variable exists so a migration can be a loop in a script;
// the prompt exists so a one-off does not require putting a passphrase in the
// shell history. Neither happens when there is no vault to open: an account
// that has never signed in has no passphrase, and asking for one would be
// asking a question with no answer.
func vaultPassphrase(email string, hasVault bool) (string, error) {
	if !hasVault {
		return "", nil
	}
	if fromEnv, ok := os.LookupEnv("BKD_VAULT_PASSPHRASE"); ok {
		return fromEnv, nil
	}
	return readPassword("Vault passphrase for " + email)
}

func parseConflict(name string) (portability.OnConflict, error) {
	switch strings.ToLower(name) {
	case "skip":
		return portability.ConflictSkip, nil
	case "rename":
		return portability.ConflictRename, nil
	case "replace":
		return portability.ConflictReplace, nil
	default:
		return "", fmt.Errorf("-on-conflict %q must be skip, rename or replace", name)
	}
}

func firstN[T any](items []T, n int) []T {
	if len(items) <= n {
		return items
	}
	return items[:n]
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
