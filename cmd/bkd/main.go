// Command bkd is the Bridgekeeper server: a self-hosted, browser-based
// SSH/SFTP/Telnet/serial client with per-user encrypted credential storage.
//
// It ships as a single static binary. Subcommands cover the whole lifecycle an
// operator needs: serve, migrate, rollback, gen-master-key and version.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/logging"
	"github.com/mrbuttshooter/securecrt/internal/server"
)

const usage = `bkd — Bridgekeeper server

Usage:
  bkd <command> [flags]

Commands:
  serve             Run the server
  migrate           Apply pending database migrations and exit
  rollback          Revert the most recent migration and exit
  gen-master-key    Create the server master key file (run once, at install)
  admin             Manage accounts (create-user, list-users, reset-vault, ...)
  test-sso          Check the single sign-on configuration against the provider
  version           Print the build version

Run "bkd <command> -h" for the flags of a specific command.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		// The logger may not be configured yet, so report to stderr directly.
		fmt.Fprintf(os.Stderr, "bkd: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest)
	case "migrate":
		return cmdMigrate(rest)
	case "rollback":
		return cmdRollback(rest)
	case "gen-master-key":
		return cmdGenMasterKey(rest)
	case "admin":
		return cmdAdmin(rest)
	case "test-sso":
		return cmdTestSSO(rest)
	case "version":
		fmt.Println(config.Version)
		return nil
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// signalContext returns a context cancelled on SIGINT or SIGTERM, so systemd
// stop and Ctrl-C both trigger the same graceful shutdown path.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", "/etc/bkd/config.yaml", "path to the configuration file")
}

func loadConfig(path string) (config.Config, error) {
	// A missing file at the default path is not an error: it lets the binary
	// run from defaults plus BKD_* environment variables, which is how it
	// behaves in a container or a quick local trial.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return config.Load("")
	}
	return config.Load(path)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := logging.Setup(cfg.Log.Level, cfg.Log.Format, os.Stderr)

	ctx, stop := signalContext()
	defer stop()

	srv, err := server.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := logging.Setup(cfg.Log.Level, cfg.Log.Format, os.Stderr)

	ctx, stop := signalContext()
	defer stop()

	return server.MigrateOnly(ctx, cfg, log)
}

func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	cfgPath := configFlag(fs)
	confirm := fs.Bool("yes", false, "confirm the rollback (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Rolling back drops tables. Requiring an explicit flag keeps it out of
	// reach of a mistyped command or an over-eager deploy script.
	if !*confirm {
		return errors.New("rollback drops schema objects; re-run with -yes to confirm")
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := logging.Setup(cfg.Log.Level, cfg.Log.Format, os.Stderr)

	ctx, stop := signalContext()
	defer stop()

	return server.RollbackOnly(ctx, cfg, log)
}

// cmdTestSSO validates the single sign-on configuration against the live
// identity provider, so the first real sign-in attempt gives a specific error
// rather than a blank page.
func cmdTestSSO(args []string) error {
	fs := flag.NewFlagSet("test-sso", flag.ExitOnError)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	return server.TestOIDC(ctx, cfg)
}

func cmdGenMasterKey(args []string) error {
	fs := flag.NewFlagSet("gen-master-key", flag.ExitOnError)
	cfgPath := configFlag(fs)
	path := fs.String("path", "", "master key path (default: vault.master_key_path from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	target := *path
	if target == "" {
		target = cfg.Vault.MasterKeyPath
	}
	return server.GenerateMasterKey(target)
}
