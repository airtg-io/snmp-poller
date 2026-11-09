// Command snmp-poller is AIrtg snmp-poller, the SNMP poller of AIrtg.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/logging"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/poller"
)

// version (the VERSION file) and commit are set at build time by the
// Makefile with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	path := flag.String("config", config.DefaultPath, "path to the YAML configuration file")
	check := flag.Bool("check", false, "validate the configuration and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	encrypt := flag.Bool("encrypt", false, "print a credential encrypted for the configuration file, and exit: -encrypt VALUE, or piped on stdin, or typed at the prompt")
	keyPath := flag.String("key", "", "key file for -encrypt (default: <global.data_dir of -config>/"+config.KeyFile+")")
	flag.Parse()

	if *showVersion {
		fmt.Printf("AIrtg snmp-poller %s (commit %s)\n", version, commit)
		return 0
	}

	if *encrypt {
		return encryptCmd(*path, *keyPath, flag.Args(), os.Stdin, os.Stdout, os.Stderr)
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q (only -encrypt takes a value)\n", flag.Arg(0))
		return 2
	}

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		return 2
	}

	if *check {
		// Building outputs validates their type-specific options too.
		outs, err := output.Build(cfg.Outputs, discardLogger())
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
			return 2
		}
		output.CloseAll(outs)
		names := make([]string, 0, len(cfg.Capabilities()))
		for _, c := range cfg.Capabilities() {
			names = append(names, c.Name)
		}
		fmt.Printf("configuration OK: %d enabled device(s), %d output(s), %d capabilities from %s (%s)\n",
			len(cfg.DeviceSpecs()), len(cfg.Outputs), len(names), cfg.Global.ConfDir, strings.Join(names, ", "))
		return 0
	}

	log, err := logging.New(cfg.Logging, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging: %v\n", err)
		return 1
	}
	defer log.Close()
	log.Info("starting AIrtg snmp-poller", "version", version, "commit", commit, "config", *path)

	// Encrypt the clear-text credentials of the (valid) configuration file.
	// A read-only file is not fatal: polling works, the file stays in clear.
	sealed, err := cfg.Seal()
	if sealed.KeyCreated {
		log.Info("credentials key generated: back it up, encrypted credentials cannot be read without it",
			"key", sealed.KeyPath)
	}
	switch {
	case err != nil:
		log.Warn("credentials not encrypted in the configuration file", "config", *path,
			"key", sealed.KeyPath, "err", err)
	case sealed.Encrypted > 0:
		log.Info("credentials encrypted in the configuration file", "config", *path,
			"count", sealed.Encrypted, "key", sealed.KeyPath)
	}

	outs, err := output.Build(cfg.Outputs, log.Logger)
	if err != nil {
		log.Error("outputs", "err", err)
		return 1
	}
	defer func() {
		if err := output.CloseAll(outs); err != nil {
			log.Error("closing outputs", "err", err)
		}
	}()

	p, err := poller.New(cfg, log.Logger, outs)
	if err != nil {
		log.Error("poller", "err", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := p.Run(ctx); err != nil {
		log.Error("poller", "err", err)
		return 1
	}
	return 0
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
