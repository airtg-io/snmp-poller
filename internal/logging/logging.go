// Package logging builds the process logger: console and/or an automatically
// rotated log file, with a configurable level, plus per-device overrides.
// Records are text (logfmt). Every timestamp is RFC 3339 with milliseconds and
// an explicit time zone, in UTC unless logging.local_time is set.
package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// Logger is the configured root logger and the resources behind it. It can
// be reconfigured while in use (see Reconfigure): every logger derived from
// it, before or after, follows the new configuration.
type Logger struct {
	*slog.Logger
	console io.Writer
	mu      sync.Mutex // serializes Reconfigure and Close
	cur     atomic.Pointer[sinks]
}

// sinks is one configuration of the logger.
type sinks struct {
	cfg     config.Logging
	level   slog.Level
	handler slog.Handler // every sink, accepting every level
	file    *fileSink    // nil without a log file
}

// Close flushes and closes the log file, if any.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.cur.Load().file; f != nil {
		return f.Close()
	}
	return nil
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
	l := &Logger{console: console}
	s, err := l.build(cfg, nil)
	if err != nil {
		return nil, err
	}
	l.cur.Store(s)
	l.Logger = slog.New(&handler{l: l})
	return l, nil
}

// Reconfigure applies cfg to the logger and every logger derived from it.
// The log file is kept open when its settings did not change; otherwise
// the new one is opened first, and on error the logger is left unchanged.
func (l *Logger) Reconfigure(cfg config.Logging) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	old := l.cur.Load()
	s, err := l.build(cfg, old)
	if err != nil {
		return err
	}
	l.cur.Store(s)
	if old.file != nil && old.file != s.file {
		return old.file.Close()
	}
	return nil
}

// build creates the sinks of cfg, reusing the log file of old when its
// settings are the same.
func (l *Logger) build(cfg config.Logging, old *sinks) (*sinks, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	// Sinks accept every record; filtering happens in the root handler so
	// device-level trace can bypass the global level.
	loc := time.UTC
	if *cfg.LocalTime {
		loc = time.Local
	}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: timeIn(loc)}
	s := &sinks{cfg: cfg, level: level}
	var hs []slog.Handler

	if *cfg.Console.Enabled {
		hs = append(hs, slog.NewTextHandler(l.console, opts))
	}
	if *cfg.File.Enabled {
		if old != nil && old.file != nil && sameFile(old.cfg, cfg) {
			s.file = old.file
		} else {
			if s.file, err = openFile(cfg); err != nil {
				return nil, err
			}
		}
		hs = append(hs, slog.NewTextHandler(s.file, opts))
	}
	s.handler = fanout(hs)
	return s, nil
}

// sameFile reports whether a and b write the same log file the same way.
func sameFile(a, b config.Logging) bool {
	return a.File.Path == b.File.Path && a.File.MaxSizeMB == b.File.MaxSizeMB &&
		*a.File.MaxBackups == *b.File.MaxBackups && *a.File.MaxAgeDays == *b.File.MaxAgeDays &&
		*a.File.Compress == *b.File.Compress && *a.LocalTime == *b.LocalTime
}

func openFile(cfg config.Logging) (*fileSink, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.File.Path), 0o755); err != nil {
		return nil, fmt.Errorf("log directory: %w", err)
	}
	lj := &lumberjack.Logger{
		Filename:   cfg.File.Path,
		MaxSize:    cfg.File.MaxSizeMB,
		MaxBackups: *cfg.File.MaxBackups,
		MaxAge:     *cfg.File.MaxAgeDays,
		Compress:   *cfg.File.Compress,
		LocalTime:  *cfg.LocalTime,
	}
	// Fail early on an unwritable path instead of on the first record.
	if _, err := lj.Write(nil); err != nil {
		return nil, fmt.Errorf("log file: %w", err)
	}
	return &fileSink{lj: lj}, nil
}

// fileSink is the rotating log file. A record written after Close (by a
// logger that read the previous configuration just before Reconfigure) is
// dropped instead of reopening the file.
type fileSink struct {
	mu     sync.RWMutex
	lj     *lumberjack.Logger
	closed bool
}

func (f *fileSink) Write(p []byte) (int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return len(p), nil
	}
	return f.lj.Write(p)
}

func (f *fileSink) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.lj.Close()
}

// TimeFormat is the layout of every timestamp in log records. The zone is
// always present: "Z" for UTC, a numeric offset otherwise.
const TimeFormat = "2006-01-02T15:04:05.000Z07:00"

// timeIn renders the record time, and any time attribute, in loc using
// TimeFormat.
func timeIn(loc *time.Location) func([]string, slog.Attr) slog.Attr {
	return func(_ []string, a slog.Attr) slog.Attr {
		if a.Value.Kind() == slog.KindTime {
			a.Value = slog.StringValue(a.Value.Time().In(loc).Format(TimeFormat))
		}
		return a
	}
}

// WithMinLevel returns a logger derived from l whose records are emitted down
// to min, regardless of the global level. Used for per-device tracing.
func WithMinLevel(l *slog.Logger, min slog.Level) *slog.Logger {
	h, ok := l.Handler().(*handler)
	if !ok || (h.min != nil && *h.min <= min) {
		return l
	}
	return slog.New(&handler{l: h.l, min: &min, ops: h.ops})
}

// handler is the handler of a Logger and of every logger derived from it.
// It filters records by the current global level (or its own min, when
// lower) and hands them to the current sinks, with its attributes and
// groups applied. The sinks derived with those is cached per configuration.
type handler struct {
	l     *Logger
	min   *slog.Level // per-device trace level; nil = global level only
	ops   []op        // WithAttrs and WithGroup calls, in order
	cache atomic.Pointer[derived]
}

// op is one WithAttrs (attrs) or WithGroup (group) call.
type op struct {
	attrs []slog.Attr
	group string
}

type derived struct {
	s *sinks
	h slog.Handler
}

func (h *handler) Enabled(_ context.Context, lvl slog.Level) bool {
	min := h.l.cur.Load().level
	if h.min != nil && *h.min < min {
		min = *h.min
	}
	return lvl >= min
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	s := h.l.cur.Load()
	d := h.cache.Load()
	if d == nil || d.s != s {
		next := s.handler
		for _, o := range h.ops {
			if o.attrs != nil {
				next = next.WithAttrs(o.attrs)
			} else {
				next = next.WithGroup(o.group)
			}
		}
		d = &derived{s: s, h: next}
		h.cache.Store(d)
	}
	return d.h.Handle(ctx, r)
}

func (h *handler) with(o op) *handler {
	return &handler{l: h.l, min: h.min, ops: append(slices.Clip(h.ops), o)}
}

func (h *handler) WithAttrs(a []slog.Attr) slog.Handler {
	if len(a) == 0 {
		return h
	}
	return h.with(op{attrs: a})
}

func (h *handler) WithGroup(n string) slog.Handler {
	if n == "" {
		return h
	}
	return h.with(op{group: n})
}

type multiHandler []slog.Handler

func fanout(hs []slog.Handler) slog.Handler {
	if len(hs) == 0 {
		return slog.DiscardHandler
	}
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
