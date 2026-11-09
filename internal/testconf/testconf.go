// Package testconf builds configurations for tests: a main configuration
// and its capabilities directory, written to a temporary directory.
package testconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// Uptime is a capability polling sysUpTime, for tests that need any metric.
const Uptime = `scalars: [{ name: sysUpTime, oid: 1.3.6.1.2.1.1.3.0 }]`

// Write creates dir/capabilities.d with one file per capability (name -> YAML) and
// returns dir, to be passed to config.Parse as the base directory.
func Write(t testing.TB, caps map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "capabilities.d")
	if err := os.Mkdir(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, doc := range caps {
		if err := os.WriteFile(filepath.Join(conf, name+".yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Parse parses main with the given capabilities, failing the test on error.
func Parse(t testing.TB, main string, caps map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Parse(strings.NewReader(main), Write(t, caps))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}
