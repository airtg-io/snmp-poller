// Package logging builds the process logger: console and/or an automatically
// rotated log file, with a configurable level, plus per-device overrides.
package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// Logger is the configured root logger and the resources behind it.
type Logger struct {
	*slog.Logger
	closers []io.Closer
}

// Close flushes and closes the log file, if any.
func (l *Logger) Close() error {
	var errs []error
	for _, c := range l.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// ParseLevel converts a configured level name into a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q", s)
}

// New builds the logger described by cfg. console is where console output
// goes (normally os.Stderr).
func New(cfg config.Logging, console io.Writer) (*Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	// Sinks accept every record; filtering happens in the root handler so
	// device-level trace can bypass the global level.
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	l := &Logger{}
	var sinks []slog.Handler

	if *cfg.Console.Enabled {
		sinks = append(sinks, newHandler(console, cfg.Console.Format, opts))
	}
	if *cfg.File.Enabled {
		if err := os.MkdirAll(filepath.Dir(cfg.File.Path), 0o755); err != nil {
			return nil, fmt.Errorf("log directory: %w", err)
		}
		lj := &lumberjack.Logger{
			Filename:   cfg.File.Path,
			MaxSize:    cfg.File.MaxSizeMB,
			MaxBackups: *cfg.File.MaxBackups,
			MaxAge:     *cfg.File.MaxAgeDays,
			Compress:   *cfg.File.Compress,
			LocalTime:  *cfg.File.LocalTime,
		}
		// Fail early on an unwritable path instead of on the first record.
		if _, err := lj.Write(nil); err != nil {
			return nil, fmt.Errorf("log file: %w", err)
		}
		l.closers = append(l.closers, lj)
		sinks = append(sinks, newHandler(lj, cfg.File.Format, opts))
	}
	l.Logger = slog.New(&levelHandler{min: level, next: fanout(sinks)})
	return l, nil
}

func newHandler(w io.Writer, format string, opts *slog.HandlerOptions) slog.Handler {
	if format == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// WithMinLevel returns a logger derived from l whose records are emitted down
// to min, regardless of the global level. Used for per-device tracing.
func WithMinLevel(l *slog.Logger, min slog.Level) *slog.Logger {
	h := l.Handler()
	if lh, ok := h.(*levelHandler); ok {
		if min >= lh.min {
			return l
		}
		return slog.New(&levelHandler{min: min, next: lh.next})
	}
	return l
}

// levelHandler filters records below min before handing them to next.
type levelHandler struct {
	min  slog.Level
	next slog.Handler
}

func (h *levelHandler) Enabled(_ context.Context, lvl slog.Level) bool { return lvl >= h.min }
func (h *levelHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.next.Handle(ctx, r)
}
func (h *levelHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &levelHandler{min: h.min, next: h.next.WithAttrs(a)}
}
func (h *levelHandler) WithGroup(n string) slog.Handler {
	return &levelHandler{min: h.min, next: h.next.WithGroup(n)}
}

type multiHandler []slog.Handler

func fanout(hs []slog.Handler) slog.Handler {
	if len(hs) == 1 {
		return hs[0]
	}
	return multiHandler(hs)
}

func (m multiHandler) Enabled(context.Context, slog.Level) bool { return true }
func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m {
		errs = append(errs, h.Handle(ctx, r.Clone()))
	}
	return errors.Join(errs...)
}
func (m multiHandler) WithAttrs(a []slog.Attr) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(a)
	}
	return out
}
func (m multiHandler) WithGroup(n string) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(n)
	}
	return out
}
