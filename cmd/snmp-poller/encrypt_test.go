package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// pipe returns a non-terminal stdin holding input.
func pipe(t *testing.T, input string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(input)
	w.Close()
	t.Cleanup(func() { r.Close() })
	return r
}

func TestEncryptCmd(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	cfgPath := filepath.Join(dir, "snmp-poller.yaml")
	os.WriteFile(cfgPath, []byte("global: { data_dir: "+dataDir+" }\n"), 0o644)
	enc := regexp.MustCompile(`^~~(?:[0-9A-F]{2})+~~\n$`)

	// Key from the configuration's data_dir, generated on first use.
	var out, errOut bytes.Buffer
	if code := encryptCmd(cfgPath, "", nil, pipe(t, "my secret\r\nignored"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !enc.MatchString(out.String()) || !strings.Contains(errOut.String(), "key generated: "+config.KeyPath(dataDir)) {
		t.Errorf("out=%q err=%q", out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), "my secret") {
		t.Error("the clear value must not be printed")
	}

	// The poller reads it back.
	os.Mkdir(filepath.Join(dir, "capabilities.d"), 0o755)
	os.WriteFile(filepath.Join(dir, "capabilities.d", "uptime.yaml"), []byte(`scalars: [{ name: up, oid: 1.3.6.1.2.1.1.3.0, unit: second }]`), 0o644)
	os.WriteFile(cfgPath, []byte("global: { data_dir: "+dataDir+" }\ndevices: [{ address: x, snmp: { version: 2c, community: "+strings.TrimSpace(out.String())+" } }]\n"), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.DeviceSpecs()[0].SNMP.Community.Reveal(); v != "my secret" {
		t.Errorf("read back %q", v)
	}

	// Explicit -key, existing key: no "generated" message.
	out.Reset()
	errOut.Reset()
	if code := encryptCmd("/nonexistent.yaml", config.KeyPath(dataDir), nil, pipe(t, "x"), &out, &errOut); code != 0 || errOut.Len() != 0 || !enc.MatchString(out.String()) {
		t.Errorf("exit %d out=%q err=%q", code, out.String(), errOut.String())
	}

	// Errors: empty value, unreadable configuration without -key.
	errOut.Reset()
	if code := encryptCmd(cfgPath, "", nil, pipe(t, "\n"), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "the value is empty") {
		t.Errorf("empty: exit %d err=%q", code, errOut.String())
	}
	errOut.Reset()
	if code := encryptCmd(filepath.Join(dir, "missing.yaml"), "", nil, pipe(t, "x"), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "use -key") {
		t.Errorf("missing config: exit %d err=%q", code, errOut.String())
	}
}

func TestEncryptCmdArgument(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key.dat")
	var out, errOut bytes.Buffer
	// The argument wins over stdin.
	if code := encryptCmd("", keyPath, []string{"from arg"}, pipe(t, "from stdin\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	}
	enc := strings.TrimSpace(out.String())
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "capabilities.d"), 0o755)
	os.WriteFile(filepath.Join(dir, "capabilities.d", "uptime.yaml"), []byte(`scalars: [{ name: up, oid: 1.3.6.1.2.1.1.3.0, unit: second }]`), 0o644)
	os.Rename(keyPath, filepath.Join(dir, "key.dat"))
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("global: { data_dir: "+dir+" }\ndevices: [{ address: x, snmp: { version: 2c, community: "+enc+" } }]\n"), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.DeviceSpecs()[0].SNMP.Community.Reveal(); v != "from arg" {
		t.Errorf("read back %q", v)
	}

	errOut.Reset()
	if code := encryptCmd("", keyPath, []string{"a", "b"}, pipe(t, ""), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "expected one value, got 2") {
		t.Errorf("two args: exit %d err=%q", code, errOut.String())
	}
	errOut.Reset()
	if code := encryptCmd("", keyPath, []string{""}, pipe(t, ""), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "empty") {
		t.Errorf("empty arg: exit %d err=%q", code, errOut.String())
	}
}
