// Command snmp-poller is the AIrtg SNMP poller.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/logging"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/poller"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	path := flag.String("config", config.DefaultPath, "path to the YAML configuration file")
	check := flag.Bool("check", false, "validate the configuration and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("snmp-poller", version)
		return 0
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
		fmt.Printf("configuration OK: %d enabled device(s), %d output(s)\n",
			len(cfg.DeviceSpecs()), len(cfg.Outputs))
		return 0
	}

	log, err := logging.New(cfg.Logging, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging: %v\n", err)
		return 1
	}
	defer log.Close()
	log.Info("starting snmp-poller", "version", version, "config", *path)

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
