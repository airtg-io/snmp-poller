package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, doc string) (*Config, error) {
	t.Helper()
	return Parse(strings.NewReader(doc))
}

func mustParse(t *testing.T, doc string) *Config {
	t.Helper()
	c, err := parse(t, doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

const minimalDevice = `
devices:
  - id: r1
    address: 10.0.0.1
    snmp: { version: 2c, community: s3cret }
    scalars:
      - { name: sysUpTime, oid: 1.3.6.1.2.1.1.3.0 }
`

func TestDefaults(t *testing.T) {
	c := mustParse(t, minimalDevice)
	g := c.Global
	if g.Threads != 250 || g.PollInterval != time.Minute || g.DiscoveryInterval != time.Hour ||
		g.StatsInterval != time.Minute || g.DataDir != "data" || g.Port != 161 || *g.Retries != 1 {
		t.Errorf("unexpected global defaults: %+v", g)
	}
	l := c.Logging
	if l.Level != "info" || !*l.Console.Enabled || !*l.File.Enabled || l.File.Path != "logs/auto-rotate.log" {
		t.Errorf("unexpected logging defaults: %+v", l)
	}
	if len(c.Outputs) != 1 || c.Outputs[0].Type != "null" {
		t.Errorf("default outputs = %+v, want one null output", c.Outputs)
	}
	specs := c.DeviceSpecs()
	if len(specs) != 1 {
		t.Fatalf("specs = %d", len(specs))
	}
	s := specs[0]
	if s.Port != 161 || s.PollInterval != time.Minute || s.DiscoveryInterval != time.Hour ||
		s.SNMP.Transport != "udp" || s.SNMP.Version != Version2c {
		t.Errorf("unexpected device spec: %+v", s)
	}
	if s.Scalars[0].OID != ".1.3.6.1.2.1.1.3.0" || s.Scalars[0].Modes[0] != ModeRaw {
		t.Errorf("scalar not normalized: %+v", s.Scalars[0])
	}
	for name := range DefaultDiscoveryScalars {
		if _, ok := s.Discovery.Scalars[name]; !ok {
			t.Errorf("default discovery scalar %s missing", name)
		}
	}
	if len(s.Outputs) != 1 || s.Outputs[0] != "null" {
		t.Errorf("device outputs = %v", s.Outputs)
	}
}

func TestDefaultConfigFileIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	if _, err := Load(filepath.Join(filepath.Dir(file), "..", "..", DefaultPath)); err != nil {
		t.Fatal(err)
	}
}

func TestReadmeExamplesAreValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNMP_COMMUNITY", "from-env")
	t.Setenv("SNMP_AUTH_PASS", "auth-pass-123")
	t.Setenv("SNMP_PRIV_PASS", "priv-pass-123")
	// Every ```yaml block in the README must be a complete, valid config.
	blocks := strings.Split(string(data), "```yaml\n")
	if len(blocks) < 2 {
		t.Fatal("no yaml examples found in README.md")
	}
	for i, b := range blocks[1:] {
		doc, _, _ := strings.Cut(b, "```")
		t.Run(fmt.Sprintf("example-%d", i+1), func(t *testing.T) {
			if _, err := parse(t, doc); err != nil {
				t.Errorf("%v\n---\n%s", err, doc)
			}
		})
	}
}

func TestInheritanceAndOverrides(t *testing.T) {
	c := mustParse(t, `
global: { poll_interval: 30s, discovery_interval: 2h, timeout: 2s, retries: 3, port: 1161 }
outputs:
  - { name: a, type: "null" }
  - { name: b, type: "null" }
credentials:
  v3:
    version: 3
    username: poller
    auth_protocol: sha-256
    auth_passphrase: authpass1
    priv_protocol: aes128
    priv_passphrase: privpass1
profiles:
  base:
    discovery:
      scalars: { model: 1.3.6.1.2.1.47.1.1.1.1.13.1 }
      columns: { ifName: 1.3.6.1.2.1.31.1.1.1.1 }
    tables:
      - name: if
        label: ifName
        include: ["^eth"]
        columns: [{ name: in, oid: 1.3.6.1.2.1.31.1.1.1.6, modes: [rate, volume, rate] }]
devices:
  - id: r1
    address: 10.0.0.1
    credential: v3
    snmp: { context_name: vrf1, context_engine_id: "0x80001F88" }
    profiles: [base]
    poll_interval: 10s
    discovery_interval: 5m
    retries: 0
    outputs: [b]
  - id: r2
    address: 10.0.0.2
    credential: v3
    profiles: [base]
`)
	r1, r2 := c.DeviceSpecs()[0], c.DeviceSpecs()[1]
	if r1.PollInterval != 10*time.Second || r1.DiscoveryInterval != 5*time.Minute || r1.Retries != 0 || r1.Port != 1161 {
		t.Errorf("r1 overrides not applied: %+v", r1)
	}
	if r2.PollInterval != 30*time.Second || r2.DiscoveryInterval != 2*time.Hour || r2.Retries != 3 || r2.Timeout != 2*time.Second {
		t.Errorf("r2 globals not inherited: %+v", r2)
	}
	s := r1.SNMP
	if s.Version != Version3 || s.SecurityLevel != AuthPriv || s.AuthProtocol != "SHA256" ||
		s.PrivProtocol != "AES" || s.ContextName != "vrf1" || s.ContextEngineID != "80001f88" {
		t.Errorf("r1 snmp not normalized: %+v", s)
	}
	if r2.SNMP.ContextName != "" {
		t.Errorf("r2 must not inherit r1's inline context")
	}
	if fmt.Sprint(r1.Outputs) != "[b]" || fmt.Sprint(r2.Outputs) != "[a b]" {
		t.Errorf("outputs: r1=%v r2=%v", r1.Outputs, r2.Outputs)
	}
	tbl := r1.Tables[0]
	if fmt.Sprint(tbl.Columns[0].Modes) != "[rate volume]" {
		t.Errorf("modes not deduplicated: %v", tbl.Columns[0].Modes)
	}
	if !tbl.Selects("eth0") || tbl.Selects("lo") {
		t.Error("include pattern not applied")
	}
	if r1.Discovery.Scalars["model"] != ".1.3.6.1.2.1.47.1.1.1.1.13.1" {
		t.Errorf("profile discovery not merged: %v", r1.Discovery.Scalars)
	}
}

func TestSecurityLevelInference(t *testing.T) {
	for _, tc := range []struct{ snmp, want string }{
		{`{ version: 3, username: u }`, NoAuthNoPriv},
		{`{ version: 3, username: u, auth_protocol: MD5, auth_passphrase: 12345678 }`, AuthNoPriv},
		{`{ version: 3, username: u, auth_protocol: SHA512, auth_passphrase: 12345678, priv_protocol: AES256C, priv_passphrase: 12345678 }`, AuthPriv},
	} {
		c := mustParse(t, `devices: [{ id: d, address: x, snmp: `+tc.snmp+`, scalars: [{ name: a, oid: 1.3 }] }]`)
		if got := c.DeviceSpecs()[0].SNMP.SecurityLevel; got != tc.want {
			t.Errorf("%s: level = %s, want %s", tc.snmp, got, tc.want)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	dev := func(extra string) string {
		return `devices: [{ id: d, address: x, snmp: { version: 2c, community: c }, scalars: [{ name: a, oid: 1.3 }]` + extra + ` }]`
	}
	for _, tc := range []struct{ doc, want string }{
		{`global: { threads: -1 }`, "threads"},
		{`logging: { level: verbose }`, "logging.level"},
		{`bogus: 1`, "field bogus not found"},
		{`devices: [{ id: "bad id", address: x }]`, "id may only contain"},
		{`devices: [{ id: d, snmp: { version: 2c, community: c } }]`, "address is required"},
		{`devices: [{ id: d, address: x, snmp: { version: 4 }, scalars: [{ name: a, oid: 1.3 }] }]`, "unsupported snmp version"},
		{`devices: [{ id: d, address: x, snmp: { version: 2c }, scalars: [{ name: a, oid: 1.3 }] }]`, "requires a community"},
		{`devices: [{ id: d, address: x, snmp: { version: 3 }, scalars: [{ name: a, oid: 1.3 }] }]`, "requires a username"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, auth_protocol: MD4 }, scalars: [{ name: a, oid: 1.3 }] }]`, "auth_protocol"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, auth_protocol: MD5, auth_passphrase: short }, scalars: [{ name: a, oid: 1.3 }] }]`, "at least 8"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, security_level: authPriv, auth_protocol: MD5, auth_passphrase: 12345678 }, scalars: [{ name: a, oid: 1.3 }] }]`, "requires priv_protocol"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, context_engine_id: zz }, scalars: [{ name: a, oid: 1.3 }] }]`, "hex"},
		{dev(`, credential: nope`), "unknown credential"},
		{dev(`, profiles: [nope]`), "unknown profile"},
		{dev(`, outputs: [nope]`), "unknown output"},
		{dev(`, tables: [{ name: t, label: ifName, columns: [{ name: c, oid: 1.3 }] }]`), "not a discovery column"},
		{dev(`, tables: [{ name: t, include: ["("], columns: [{ name: c, oid: 1.3 }] }]`), "include"},
		{dev(`, tables: [{ name: t }]`), "at least one column"},
		{`devices: [{ id: d, address: x, snmp: { version: 2c, community: c }, scalars: [{ name: a, oid: x.y }] }]`, "invalid oid"},
		{`devices: [{ id: d, address: x, snmp: { version: 2c, community: c }, scalars: [{ name: a, oid: 1.3, modes: [delta] }] }]`, "invalid mode"},
		{`devices: [{ id: d, address: x, snmp: { version: 2c, community: c } }]`, "nothing to poll"},
		{`devices: [{ id: d, address: x, snmp: { version: 2c, community: c }, scalars: [{ name: a, oid: 1.3 }, { name: a, oid: 1.4 }] }]`, "duplicate scalar"},
		{dev(``) + "\n" + `outputs: [{ name: a, type: "null" }, { name: a, type: "null" }]`, "duplicate name"},
	} {
		_, err := parse(t, tc.doc)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\n  err = %v, want containing %q", tc.doc, err, tc.want)
		}
	}
}

func TestDisabledDeviceSkipped(t *testing.T) {
	c := mustParse(t, `devices: [{ id: d, address: x, enabled: false }]`)
	if len(c.DeviceSpecs()) != 0 {
		t.Error("disabled device must not be resolved")
	}
}

func TestUnusedCredentialNotValidated(t *testing.T) {
	mustParse(t, `credentials: { unused: { version: 2c, community: "${UNSET_VAR_FOR_TEST}" } }`)
}

func TestSecretNeverLeaks(t *testing.T) {
	t.Setenv("TEST_COMMUNITY", "super-secret-community")
	c := mustParse(t, `
devices:
  - id: d
    address: x
    snmp: { version: 2c, community: "${TEST_COMMUNITY}" }
    scalars: [{ name: a, oid: 1.3 }]
`)
	s := c.DeviceSpecs()[0].SNMP
	if s.Community.Reveal() != "super-secret-community" {
		t.Fatalf("env not expanded: %q", s.Community.Reveal())
	}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "snmp", s, "community", s.Community)
	js, _ := json.Marshal(s)
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), buf.String(), string(js)} {
		if strings.Contains(out, "super-secret") {
			t.Errorf("secret leaked: %s", out)
		}
	}
	// Validation errors must not echo secrets either.
	_, err := parse(t, `devices: [{ id: d, address: x, snmp: { version: 3, username: u, auth_protocol: MD5, auth_passphrase: leak } , scalars: [{ name: a, oid: 1.3 }] }]`)
	if err == nil || strings.Contains(err.Error(), "leak") {
		t.Errorf("err = %v", err)
	}
}
