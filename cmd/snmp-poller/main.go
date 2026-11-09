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
		fmt.Printf("configuration OK: %d file(s) (%s), %d enabled device(s), %d output(s), %d capabilities from %s (%s)\n",
			len(cfg.Files()), strings.Join(cfg.Files(), ", "), len(cfg.DeviceSpecs()), len(cfg.Outputs),
			len(names), cfg.Global.CapabilitiesDir, strings.Join(names, ", "))
		return 0
	}

	log, err := logging.New(cfg.Logging, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging: %v\n", err)
		return 1
	}
	defer log.Close()
	log.Info("starting AIrtg snmp-poller", "version", version, "commit", commit, "config", *path,
		"files", len(cfg.Files()), "devices", len(cfg.DeviceSpecs()))
	if len(cfg.DeviceSpecs()) == 0 {
		log.Warn("no enabled device: add devices to a file of the include directory",
			"include_dir", cfg.Global.IncludeDir)
	}

	// Encrypt the clear-text credentials of the (valid) configuration files.
	poller.Seal(cfg, log.Logger)

	outs, err := output.Build(cfg.Outputs, log.Logger)
	if err != nil {
		log.Error("outputs", "err", err)
		return 1
	}
	p, err := poller.New(cfg, log.Logger, outs) // owns outs from now on
	if err != nil {
		output.CloseAll(outs)
		log.Error("poller", "err", err)
		return 1
	}
	// Reload on file changes (global.hot_reload) and on SIGHUP.
	p.EnableReload(config.Load, log.Reconfigure)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			log.Info("SIGHUP received: reloading the configuration")
			p.Reload()
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := p.Run(ctx); err != nil {
		log.Error("poller", "err", err)
		return 1
	}
	return 0
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
