package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/logging"
	"github.com/mrbuttshooter/securecrt/internal/server"
	"golang.org/x/term"
)

const adminUsage = `bkd admin — account administration

Usage:
  bkd admin <subcommand> [flags]

Subcommands:
  create-user    Create a local account
  list-users     List accounts
  set-admin      Grant or revoke administrator rights
  disable-user   Disable an account and end its sessions
  enable-user    Re-enable a disabled account
  reset-vault    Destroy a user's vault and everything it protects

Local accounts exist for break-glass access when single sign-on is
unavailable. Create at least one administrator before rollout, and keep its
password somewhere your team can reach during an outage.
`

func cmdAdmin(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, adminUsage)
		return errors.New("no admin subcommand given")
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "create-user":
		return adminCreateUser(rest)
	case "list-users":
		return adminListUsers(rest)
	case "set-admin":
		return adminSetAdmin(rest)
	case "disable-user":
		return adminSetDisabled(rest, true)
	case "enable-user":
		return adminSetDisabled(rest, false)
	case "reset-vault":
		return adminResetVault(rest)
	case "-h", "--help", "help":
		fmt.Print(adminUsage)
		return nil
	default:
		fmt.Fprint(os.Stderr, adminUsage)
		return fmt.Errorf("unknown admin subcommand %q", sub)
	}
}

// adminContext loads configuration and opens the service layer.
func adminContext(cfgPath string) (context.Context, context.CancelFunc, config.Config, *server.Admin, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, nil, config.Config{}, nil, err
	}
	// Quiet by default: an operator running an admin command wants its
	// output, not migration chatter.
	log := logging.Setup("warn", "text", os.Stderr)

	ctx, cancel := signalContext()

	adm, err := server.NewAdmin(ctx, cfg, log)
	if err != nil {
		cancel()
		return nil, nil, config.Config{}, nil, err
	}
	return ctx, cancel, cfg, adm, nil
}

func adminCreateUser(args []string) error {
	fs := flag.NewFlagSet("create-user", flag.ExitOnError)
	cfgPath := configFlag(fs)
	email := fs.String("email", "", "email address (required)")
	name := fs.String("name", "", "display name")
	admin := fs.Bool("admin", false, "grant administrator rights")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("-email is required")
	}

	ctx, cancel, _, adm, err := adminContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer adm.Close()

	password, err := readPasswordTwice("Password for " + *email)
	if err != nil {
		return err
	}

	u, err := adm.CreateUser(ctx, *email, *name, password, *admin)
	if err != nil {
		return err
	}

	fmt.Printf("\nCreated %s\n", u.Email)
	fmt.Printf("  id:    %s\n", u.ID)
	fmt.Printf("  admin: %v\n\n", u.IsAdmin)
	fmt.Println("This account has no vault yet. Signing in for the first time will")
	fmt.Println("prompt for a vault passphrase, which is what protects stored keys.")
	return nil
}

func adminListUsers(args []string) error {
	fs := flag.NewFlagSet("list-users", flag.ExitOnError)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel, _, adm, err := adminContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer adm.Close()

	list, err := adm.ListUsers(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("No accounts yet. Create one with: bkd admin create-user -email you@example.com -admin")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tSIGN-IN\tADMIN\tVAULT\t2FA\tSTATE\tLAST LOGIN")

	for _, u := range list {
		signIn := "local"
		switch {
		case u.IsSSO() && u.CanSignInLocally():
			signIn = "sso+local"
		case u.IsSSO():
			signIn = "sso"
		case !u.CanSignInLocally():
			signIn = "none"
		}

		vaultState := "not set up"
		if u.HasVault() {
			vaultState = string(u.UnlockKind)
		}

		state := "active"
		if u.IsDisabled {
			state = "disabled"
		}

		lastLogin := "never"
		if u.LastLoginAt != nil {
			lastLogin = u.LastLoginAt.Format(time.RFC3339)
		}

		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%v\t%s\t%s\n",
			u.Email, signIn, u.IsAdmin, vaultState, u.TOTPEnabled, state, lastLogin)
	}
	return tw.Flush()
}

func adminSetAdmin(args []string) error {
	fs := flag.NewFlagSet("set-admin", flag.ExitOnError)
	cfgPath := configFlag(fs)
	email := fs.String("email", "", "email address (required)")
	revoke := fs.Bool("revoke", false, "revoke rather than grant")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("-email is required")
	}

	ctx, cancel, _, adm, err := adminContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer adm.Close()

	if err := adm.SetAdmin(ctx, *email, !*revoke); err != nil {
		return err
	}

	if *revoke {
		fmt.Printf("Revoked administrator rights from %s\n", *email)
	} else {
		fmt.Printf("Granted administrator rights to %s\n", *email)
	}
	return nil
}

func adminSetDisabled(args []string, disable bool) error {
	name := "enable-user"
	if disable {
		name = "disable-user"
	}

	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cfgPath := configFlag(fs)
	email := fs.String("email", "", "email address (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("-email is required")
	}

	ctx, cancel, _, adm, err := adminContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer adm.Close()

	revoked, err := adm.SetDisabled(ctx, *email, disable)
	if err != nil {
		return err
	}

	if disable {
		fmt.Printf("Disabled %s and ended %d session(s).\n", *email, revoked)
		fmt.Println("Their stored credentials are untouched, so this can be reversed.")
	} else {
		fmt.Printf("Enabled %s. They will need to sign in again.\n", *email)
	}
	return nil
}

func adminResetVault(args []string) error {
	fs := flag.NewFlagSet("reset-vault", flag.ExitOnError)
	cfgPath := configFlag(fs)
	email := fs.String("email", "", "email address (required)")
	confirm := fs.Bool("yes", false, "confirm this destroys the user's credentials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("-email is required")
	}

	// This is the one genuinely unrecoverable operation in the system, so it
	// takes an explicit flag and then asks again.
	if !*confirm {
		return errors.New("this permanently destroys the user's stored credentials; re-run with -yes to confirm")
	}

	ctx, cancel, _, adm, err := adminContext(*cfgPath)
	if err != nil {
		return err
	}
	defer cancel()
	defer adm.Close()

	u, err := adm.FindUser(ctx, *email)
	if err != nil {
		return err
	}

	count, err := adm.CountCredentials(ctx, u.ID)
	if err != nil {
		return err
	}

	fmt.Printf("\nThis will permanently destroy %s's vault.\n\n", u.Email)
	fmt.Printf("  %d stored credential(s) will be deleted and cannot be recovered.\n", count)
	fmt.Println("  Their team memberships will be cleared and must be re-granted.")
	fmt.Println("  Their two-factor enrolment will be removed.")
	fmt.Println()
	fmt.Println("There is no key escrow: the server cannot decrypt these credentials,")
	fmt.Println("which is exactly why a forgotten passphrase cannot be recovered.")
	fmt.Println()

	if !askYesNo("Type the user's email address to confirm", u.Email) {
		fmt.Println("Cancelled. Nothing was changed.")
		return nil
	}

	if err := adm.ResetVault(ctx, u); err != nil {
		return err
	}

	fmt.Printf("\nVault reset for %s. They will be asked to set a new passphrase at next sign-in.\n", u.Email)
	return nil
}

// readPassword prompts once, without echoing.
//
// Used where the secret is being checked against something that already
// exists — a vault passphrase — so a typo is caught by the check rather than
// by a confirmation prompt.
func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading passphrase from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	secret, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return string(secret), nil
}

// readPasswordTwice prompts without echoing and requires confirmation.
func readPasswordTwice(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// A non-interactive caller — a provisioning script — reads one line
		// from stdin. No confirmation is possible or useful there.
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	fmt.Printf("%s: ", prompt)
	first, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}

	fmt.Print("Repeat password: ")
	second, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}

	if string(first) != string(second) {
		return "", errors.New("the passwords did not match")
	}
	if len(first) < 12 {
		return "", errors.New("the password must be at least 12 characters")
	}
	return string(first), nil
}

// askYesNo requires the operator to type an exact confirmation string.
//
// A y/n prompt is too easy to answer reflexively for an irreversible action.
func askYesNo(prompt, expected string) bool {
	fmt.Printf("%s: ", prompt)

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == expected
}
