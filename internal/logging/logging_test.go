package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/testconf"
)

func cfg(t *testing.T, doc string) config.Logging {
	t.Helper()
	return testconf.Parse(t, doc, map[string]string{"uptime": testconf.Uptime}).Logging
}

func TestConsoleAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "snmp-poller.log")
	var console bytes.Buffer
	l, err := New(cfg(t, `logging: { level: warn, file: { path: `+path+` } }`), &console)
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hidden")
	l.Warn("shown", "device", "r1")
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(console.String(), "hidden") || !strings.Contains(console.String(), "msg=shown device=r1") {
		t.Errorf("console = %q", console.String())
	}
	if strings.Contains(string(data), "hidden") || !strings.Contains(string(data), "msg=shown device=r1") {
		t.Errorf("file = %q", data)
	}
}

func TestDisabledSinks(t *testing.T) {
	var console bytes.Buffer
	l, err := New(cfg(t, `logging: { console: { enabled: false }, file: { enabled: false } }`), &console)
	if err != nil {
		t.Fatal(err)
	}
	l.Error("nowhere")
	if console.Len() != 0 {
		t.Error("console disabled but written")
	}
}

func TestWithMinLevel(t *testing.T) {
	var console bytes.Buffer
	l, err := New(cfg(t, `logging: { level: info, file: { enabled: false } }`), &console)
	if err != nil {
		t.Fatal(err)
	}
	traced := WithMinLevel(l.With("device", "r1"), slog.LevelDebug)
	traced.Debug("traced detail")
	l.With("device", "r2").Debug("untraced detail")
	out := console.String()
	if !strings.Contains(out, "traced detail") || !strings.Contains(out, "device=r1") {
		t.Errorf("trace logger must log debug: %q", out)
	}
	if strings.Contains(out, "untraced") {
		t.Errorf("global level must still apply to other devices: %q", out)
	}
}

func TestUnwritableFile(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	os.WriteFile(blocker, nil, 0o644)
	_, err := New(cfg(t, `logging: { file: { path: `+filepath.Join(blocker, "x.log")+` } }`), &bytes.Buffer{})
	if err == nil {
		t.Error("expected an error for an unwritable log path")
	}
}

func TestTimestampsCarryZone(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("TEST", 2*3600)
	t.Cleanup(func() { time.Local = saved })
	at := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		doc  string
		want *regexp.Regexp
	}{
		{`logging: { file: { enabled: false } }`,
			regexp.MustCompile(`^time=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z level=INFO msg=m at=2026-11-08T10:00:00\.000Z\n$`)},
		{`logging: { local_time: true, file: { enabled: false } }`,
			regexp.MustCompile(`^time=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+02:00 level=INFO msg=m at=2026-11-08T12:00:00\.000\+02:00\n$`)},
	} {
		var console bytes.Buffer
		l, err := New(cfg(t, tc.doc), &console)
		if err != nil {
			t.Fatal(err)
		}
		l.Info("m", "at", at)
		if !tc.want.MatchString(console.String()) {
			t.Errorf("%s: got %q", tc.doc, console.String())
		}
	}
}
