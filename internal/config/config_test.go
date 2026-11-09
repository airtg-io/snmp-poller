package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// uptime is a minimal capability, for tests that need one.
const uptime = `scalars: [{ name: sysUpTime, oid: 1.3.6.1.2.1.1.3.0 }]`

// writeCaps creates dir/capabilities.d with one file per capability and returns dir.
func writeCaps(t *testing.T, caps map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "capabilities.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, doc := range caps {
		if err := os.WriteFile(filepath.Join(dir, "capabilities.d", name), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// parse parses doc with a single "uptime" capability.
func parse(t *testing.T, doc string) (*Config, error) {
	t.Helper()
	return parseWith(t, doc, map[string]string{"uptime.yaml": uptime})
}

func parseWith(t *testing.T, doc string, caps map[string]string) (*Config, error) {
	t.Helper()
	return Parse(strings.NewReader(doc), writeCaps(t, caps))
}

func repoPath(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", ".."}, parts...)...)
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
`

func TestDefaults(t *testing.T) {
	c := mustParse(t, minimalDevice)
	g := c.Global
	if g.Threads != 250 || g.PollInterval != time.Minute || g.DiscoveryInterval != time.Hour ||
		g.StatsInterval != time.Minute || g.DataDir != "data" || g.Port != 161 || *g.Retries != 1 {
		t.Errorf("unexpected global defaults: %+v", g)
	}
	l := c.Logging
	if l.Level != "info" || !*l.Console.Enabled || !*l.File.Enabled || l.File.Path != "logs/snmp-poller.log" ||
		*l.LocalTime || !*l.File.Compress {
		t.Errorf("unexpected logging defaults: %+v", l)
	}
	if len(c.Sinks) != 0 {
		t.Errorf("default sinks = %+v, want none", c.Sinks)
	}
	specs := c.DeviceSpecs()
	if len(specs) != 1 {
		t.Fatalf("specs = %d", len(specs))
	}
	s := specs[0]
	if s.Port != 161 || s.PollInterval != time.Minute || s.DiscoveryInterval != time.Hour ||
		s.Transport != TransportUDP || s.Walk != WalkBulk || s.SNMP.Version != Version2c || s.VaultPath != "" {
		t.Errorf("unexpected device spec: %+v", s)
	}
	if len(s.Capabilities) != 1 || s.Capabilities[0].Name != "uptime" {
		t.Fatalf("capabilities = %+v", s.Capabilities)
	}
	if sc := s.Capabilities[0].Scalars[0]; sc.OID != ".1.3.6.1.2.1.1.3.0" || sc.Modes[0] != ModeRaw {
		t.Errorf("scalar not normalized: %+v", sc)
	}
	if filepath.Base(g.CapabilitiesDir) != "capabilities.d" || !filepath.IsAbs(g.CapabilitiesDir) {
		t.Errorf("capabilities_dir = %q, want <base dir>/capabilities.d", g.CapabilitiesDir)
	}
	if filepath.Base(g.IncludeDir) != "conf.d" || !filepath.IsAbs(g.IncludeDir) {
		t.Errorf("include_dir = %q, want <base dir>/conf.d", g.IncludeDir)
	}
	if len(s.Sinks) != 0 {
		t.Errorf("device sinks = %v", s.Sinks)
	}
}

// shippedFiles returns the configuration files shipped in etc/ (the main
// file and the examples of etc/conf.d), not local files that are ignored
// by git, such as etc/conf.d/*.yaml.
func shippedFiles(t *testing.T) []string {
	t.Helper()
	examples, err := filepath.Glob(repoPath("etc", "conf.d", "*.example"))
	if err != nil || len(examples) == 0 {
		t.Fatalf("no example in etc/conf.d (%v)", err)
	}
	return append([]string{repoPath(DefaultPath)}, examples...)
}

// shippedDir copies the shipped main configuration and capabilities to a
// temporary directory, with the given files in its conf.d (name ->
// content), and returns the path of the main file. Local files of
// etc/conf.d are never read.
func shippedDir(t *testing.T, include map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	copyFile := func(src, dst string) {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	main := filepath.Join(dir, "snmp-poller.yaml")
	copyFile(repoPath(DefaultPath), main)
	for _, d := range []string{"capabilities.d", "conf.d"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	caps, err := filepath.Glob(repoPath("etc", "capabilities.d", "*.yaml"))
	if err != nil || len(caps) == 0 {
		t.Fatalf("no shipped capability (%v)", err)
	}
	for _, c := range caps {
		copyFile(c, filepath.Join(dir, "capabilities.d", filepath.Base(c)))
	}
	for name, doc := range include {
		if err := os.WriteFile(filepath.Join(dir, "conf.d", name), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return main
}

// The shipped configuration is a template: running the poller with it
// encrypts the credentials of its examples with a local key, which must
// not be committed (nobody else has that key).
func TestDefaultConfigFileNotSealed(t *testing.T) {
	for _, file := range shippedFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if encrypted := regexp.MustCompile(`~~(?:[0-9A-Fa-f]{2})+~~`).FindString(line); encrypted != "" {
				t.Errorf("%s:%d holds an encrypted credential: the poller was run with the shipped file, "+
					"which encrypted it with a local key. Put the clear example value back "+
					"(git checkout %s) and run with a copy (-config).", file, i+1, file)
			}
		}
	}
}

// The shipped main file is valid on its own and configures no device:
// devices go in files of etc/conf.d.
func TestDefaultConfigFileIsValid(t *testing.T) {
	data, err := os.ReadFile(repoPath(DefaultPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\ndevices:") || strings.Contains(string(data), "\nvault:") {
		t.Errorf("%s configures devices or vault: they belong in etc/conf.d", DefaultPath)
	}
	c, err := Load(shippedDir(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Devices) != 0 || c.Vault != nil || len(c.Files()) != 1 {
		t.Errorf("devices = %d, vault = %v, files = %v: want none, nil, the main file", len(c.Devices), c.Vault, c.Files())
	}
	if filepath.Base(c.Global.CapabilitiesDir) != "capabilities.d" || filepath.Base(c.Global.IncludeDir) != "conf.d" {
		t.Errorf("capabilities_dir = %q, include_dir = %q", c.Global.CapabilitiesDir, c.Global.IncludeDir)
	}
	caps := map[string]*Capability{}
	for _, cp := range c.Capabilities() {
		caps[cp.Name] = cp
	}
	sys := caps["system"]
	if sys == nil || len(sys.Detect) != 0 {
		t.Fatalf("system capability missing or not applied to every device: %+v", sys)
	}
	for name, oid := range map[string]string{
		"sysDescr": "1.1.0", "sysObjectID": "1.2.0", "sysUpTime": "1.3.0",
		"sysContact": "1.4.0", "sysName": "1.5.0", "sysLocation": "1.6.0",
	} {
		if got := sys.Discovery.Scalars[name]; got != ".1.3.6.1.2.1."+oid {
			t.Errorf("system discovery %s = %q", name, got)
		}
	}
	ifs := caps["interfaces"]
	if ifs == nil || len(ifs.Detect) != 0 || len(ifs.Tables) != 1 {
		t.Fatalf("interfaces capability missing or not applied to every device: %+v", ifs)
	}
	hc := ifs.Tables[0].HighCapacity
	if hc == nil || hc.Probe != ".1.3.6.1.2.1.31.1.1.1.6" || hc.Speed != "ifSpeed" || hc.Above != 100_000_000 {
		t.Errorf("interfaces high_capacity = %+v", hc)
	}
	if e := caps["entity"]; e == nil || len(e.Detect) != 1 {
		t.Errorf("entity capability must be detected: %+v", e)
	}
}

// The examples of etc/conf.d are valid once copied to a *.yaml file.
func TestDefaultConfigExamples(t *testing.T) {
	t.Setenv("SNMP_AUTH_PASS", "auth-pass-123")
	t.Setenv("SNMP_PRIV_PASS", "priv-pass-123")
	include := map[string]string{}
	for _, f := range shippedFiles(t)[1:] {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		include[strings.TrimSuffix(filepath.Base(f), ".example")] = string(data)
	}
	c, err := Load(shippedDir(t, include))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range c.DeviceSpecs() {
		got = append(got, s.ID+" "+s.SNMP.Version)
	}
	if want := []string{"192.0.2.10-161 2c", "core-1 3"}; !slices.Equal(got, want) {
		t.Errorf("devices = %q, want %q", got, want)
	}
}

// readmeBase returns a directory holding a copy of the shipped capabilities
// (capabilities.d), to check README examples without local files.
func readmeBase(t *testing.T) string {
	return filepath.Dir(shippedDir(t, nil))
}

// Every ```yaml block of the README must be valid. A block whose first line
// is "# capabilities.d/<name>.yaml" is a capability file; one whose first
// line is "# conf.d/<name>.yaml" is a file of the include directory, checked
// with the shipped main file; any other block is a complete main
// configuration. All are checked against the shipped capabilities.
func TestReadmeExamplesAreValid(t *testing.T) {
	data, err := os.ReadFile(repoPath("README.md"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNMP_COMMUNITY", "from-env")
	t.Setenv("SNMP_AUTH_PASS", "auth-pass-123")
	t.Setenv("SNMP_PRIV_PASS", "priv-pass-123")
	t.Setenv("VAULT_TOKEN", "vault-token")
	t.Setenv("PRIV_PASS", "priv-pass-123")
	blocks := strings.Split(string(data), "```yaml\n")
	if len(blocks) < 2 {
		t.Fatal("no yaml examples found in README.md")
	}
	var caps, includes, mains int
	for i, b := range blocks[1:] {
		doc, _, _ := strings.Cut(b, "```")
		first, _, _ := strings.Cut(doc, "\n")
		t.Run(fmt.Sprintf("example-%d", i+1), func(t *testing.T) {
			if strings.HasPrefix(first, "# prometheus.yml") {
				return // configuration of another program
			}
			if file, ok := strings.CutPrefix(first, "# capabilities.d/"); ok {
				file, _, _ = strings.Cut(file, " ")
				caps++
				name := strings.TrimSuffix(file, ".yaml")
				if _, err := ParseCapability(name, strings.NewReader(doc)); err != nil {
					t.Errorf("%v\n---\n%s", err, doc)
				}
				return
			}
			if file, ok := strings.CutPrefix(first, "# conf.d/"); ok {
				file, _, _ = strings.Cut(file, " ")
				includes++
				if _, err := Load(shippedDir(t, map[string]string{file: doc})); err != nil {
					t.Errorf("%v\n---\n%s", err, doc)
				}
				return
			}
			mains++
			if _, err := Parse(strings.NewReader(doc), readmeBase(t)); err != nil {
				t.Errorf("%v\n---\n%s", err, doc)
			}
		})
	}
	if caps == 0 || includes == 0 || mains == 0 {
		t.Errorf("found %d capability, %d conf.d and %d main examples, want all three", caps, includes, mains)
	}
}

func TestInheritanceAndOverrides(t *testing.T) {
	c, err := parseWith(t, `
global: { poll_interval: 30s, discovery_interval: 2h, timeout: 2s, retries: 3, port: 1161 }
sinks:
  - { id: a, type: prometheus, url: "http://prom:9090/api/v1/write" }
  - { id: b, type: prometheus, url: "http://prom:9090/api/v1/write" }
devices:
  - id: r1
    address: 10.0.0.1
    snmp: &v3
      version: 3
      username: poller
      auth_protocol: sha-256
      auth_password: authpass1
      priv_protocol: aes128
      context_name: vrf1
      context_engine_id: "0x80001F88"
    poll_interval: 10s
    discovery_interval: 5m
    retries: 0
    sinks: [b]
    exclude: [vendor]
    include: { if: ["^ge-"] }
  - id: r2
    address: 10.0.0.2
    snmp: *v3 # a YAML alias reuses r1's block
`, map[string]string{
		"base.yaml": `
discovery:
  scalars: { model: 1.3.6.1.2.1.47.1.1.1.1.13.1 }
  columns: { ifName: 1.3.6.1.2.1.31.1.1.1.1, ifSpeed: 1.3.6.1.2.1.2.2.1.5 }
tables:
  - name: if
    label: ifName
    include: ["^eth"]
    high_capacity: { probe: 1.3.6.1.2.1.31.1.1.1.1, speed: ifSpeed }
    columns:
      - { name: in, oid: 1.3.6.1.2.1.2.2.1.10, hc_oid: 1.3.6.1.2.1.31.1.1.1.6, modes: [rate, volume, rate] }
`,
		"vendor.yml": `
detect: [1.3.6.1.4.1.9]
scalars: [{ name: cpu, oid: .1.3.6.1.4.1.9.9.109.1.1.1.1.8.1 }]
`,
		"README.txt": "not a capability",
	})
	if err != nil {
		t.Fatal(err)
	}
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
	if s.PrivPassword.Reveal() != "authpass1" {
		t.Error("priv_password must default to auth_password")
	}
	if r2.SNMP.Username != "poller" || r2.SNMP.AuthPassword.Reveal() != "authpass1" || r2.SNMP.SecurityLevel != AuthPriv {
		t.Errorf("r2 must reuse r1's snmp block through the alias: %+v", r2.SNMP)
	}
	if fmt.Sprint(r1.Sinks) != "[b]" || fmt.Sprint(r2.Sinks) != "[a b]" {
		t.Errorf("sinks: r1=%v r2=%v", r1.Sinks, r2.Sinks)
	}

	names := func(caps []*Capability) string {
		var n []string
		for _, c := range caps {
			n = append(n, c.Name)
		}
		return fmt.Sprint(n)
	}
	if got := names(c.Capabilities()); got != "[base vendor]" {
		t.Errorf("loaded capabilities = %s (.yaml and .yml only, sorted)", got)
	}
	if got := names(r1.Capabilities); got != "[base]" {
		t.Errorf("r1 capabilities = %s, want vendor excluded", got)
	}
	if got := names(r2.Capabilities); got != "[base vendor]" {
		t.Errorf("r2 capabilities = %s, want every capability", got)
	}

	base := c.Capabilities()[0]
	if base.Discovery.Scalars["model"] != ".1.3.6.1.2.1.47.1.1.1.1.13.1" {
		t.Errorf("discovery not normalized: %v", base.Discovery.Scalars)
	}
	col := base.Tables[0].Columns[0]
	if fmt.Sprint(col.Modes) != "[rate volume]" || col.HCOID != ".1.3.6.1.2.1.31.1.1.1.6" {
		t.Errorf("column not normalized: %+v", col)
	}
	if hc := base.Tables[0].HighCapacity; hc.Above != DefaultHighCapacitySpeed {
		t.Errorf("high_capacity.above default = %d", hc.Above)
	}
	if c.Capabilities()[1].Detect[0] != ".1.3.6.1.4.1.9" {
		t.Errorf("detect not normalized: %v", c.Capabilities()[1].Detect)
	}

	r1t, r2t := r1.Capabilities[0].Tables[0], r2.Capabilities[0].Tables[0]
	if !r2t.Selects("eth0") || r2t.Selects("ge-0/0/0") {
		t.Error("capability include pattern not applied")
	}
	if !r1t.Selects("ge-0/0/0") || r1t.Selects("eth0") {
		t.Error("device include override not applied")
	}
	if !base.Tables[0].Selects("eth0") || base.Tables[0].Selects("ge-0/0/0") {
		t.Error("device include override leaked into the shared capability")
	}
}

func TestSecurityLevelInference(t *testing.T) {
	for _, tc := range []struct{ snmp, want string }{
		{`{ version: 3, username: u }`, NoAuthNoPriv},
		{`{ version: 3, username: u, auth_protocol: MD5, auth_password: 12345678 }`, AuthNoPriv},
		{`{ version: 3, username: u, auth_protocol: SHA512, auth_password: 12345678, priv_protocol: AES256C, priv_password: 12345678 }`, AuthPriv},
	} {
		c := mustParse(t, `devices: [{ id: d, address: x, snmp: `+tc.snmp+` }]`)
		if got := c.DeviceSpecs()[0].SNMP.SecurityLevel; got != tc.want {
			t.Errorf("%s: level = %s, want %s", tc.snmp, got, tc.want)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	dev := func(extra string) string {
		return `devices: [{ id: d, address: x, snmp: { version: 2c, community: c }` + extra + ` }]`
	}
	for _, tc := range []struct{ doc, want string }{
		{`global: { threads: -1 }`, "threads"},
		{`logging: { level: verbose }`, "logging.level"},
		{`bogus: 1`, "field bogus not found"},
		{`profiles: {}`, "field profiles not found"},
		{`global: { capabilities_dir: nope }`, "capabilities: open"},
		{`devices: [{ id: "bad id", address: x }]`, "id may only contain"},
		{`devices: [{ id: key.dat, address: x }]`, "is reserved"},
		{`devices: [{ id: d, snmp: { version: 2c, community: c } }]`, "devices[0]: address is required"},
		{`devices: [{ id: d, address: x }]`, "snmp is required"},
		{`credentials: {}`, "field credentials not found"},
		{dev(`, credential: nope`), "field credential not found"},
		{`devices: [{ address: x, snmp: { version: 2c, community: c, transport: tcp } }]`, "field transport not found in type config.SNMP"},
		{`devices: [{ address: x, snmp: { version: 2c, community: c, auth_passphrase: x } }]`, "field auth_passphrase not found"},
		// Same agent twice: by default id, explicit ids, or equivalent addresses.
		{`devices: [{ address: 10.0.0.1, enabled: false }, { address: 10.0.0.1, port: 161 }]`, `device "10.0.0.1-161": duplicate id`},
		{`devices: [{ id: a, address: 10.0.0.1 }, { id: b, address: 10.0.0.1 }]`, `device "b": address 10.0.0.1 port 161 is already used by device "a"`},
		{`devices: [{ id: a, address: "::ffff:10.0.0.1" }, { id: b, address: 10.0.0.1 }]`, "already used"},
		{`devices: [{ id: a, address: "2001:db8::1" }, { id: b, address: "2001:DB8:0::1" }]`, "already used"},
		{`devices: [{ id: a, address: Router.example.net. }, { id: b, address: router.example.net }]`, "already used"},
		{`devices: [{ id: a, address: x, snmp: { version: 3, username: u, context_name: c1 } }, { id: b, address: x, snmp: { version: 3, username: u, context_name: c1 } }]`, "already used"},
		{`global: { transport: sctp }`, `global.transport "sctp": must be udp or tcp`},
		{`global: { walk: fast }`, `global.walk "fast": must be bulk or getnext`},
		{dev(`, transport: sctp`), `transport "sctp"`},
		{dev(`, walk: fast`), `walk "fast"`},
		{`devices: [{ id: d, address: x, walk: bulk, snmp: { version: 1, community: c } }]`, "bulk is not available in SNMPv1"},
		{dev(`, snmp: { vault: true }`), "mapping key \"snmp\" already defined"},
		{`devices: [{ id: d, address: x, snmp: { vault: true } }]`, "snmp.vault requires a vault section"},
		{`devices: [{ id: d, address: x, snmp: { vault: [a] } }]`, "vault must be true, false or a secret path"},
		{`devices: [{ id: d, address: x, snmp: { vault: "/" } }]`, "vault path is empty"},
		{`vault: { address: "vault:8200", auth: { method: token } }`, "must be an http:// or https:// URL"},
		{`vault: { auth: { method: token } }`, "vault.address is required"},
		{`vault: { address: "https://v", auth: { method: ldap } }`, `vault.auth.method "ldap"`},
		{`vault: { address: "https://v", kv_version: 3, auth: { method: token } }`, "kv_version must be 1 or 2"},
		{`vault: { address: "https://v", auth: { method: token, bogus: 1 } }`, "field bogus not found"},
		{vaultDev(`{ method: token }`), "method token requires token"},
		{vaultDev(`{ method: approle, secret_id: s }`), "method approle requires role_id"},
		{vaultDev(`{ method: approle, role_id: r }`), "method approle requires secret_id"},
		{vaultDev(`{ method: userpass, username: u }`), "method userpass requires password"},
		{vaultDev(`{ method: kubernetes }`), "method kubernetes requires role"},
		{`devices: [{ id: d, address: x, snmp: { version: 4 } }]`, "unsupported snmp version"},
		{`devices: [{ id: d, address: x, snmp: { version: 2c } }]`, "requires a community"},
		{`devices: [{ id: d, address: x, snmp: { version: 3 } }]`, "requires a username"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, auth_protocol: MD4 } }]`, "auth_protocol"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, auth_protocol: MD5, auth_password: short } }]`, "at least 8"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, security_level: authPriv, auth_protocol: MD5, auth_password: 12345678 } }]`, "requires priv_protocol"},
		{`devices: [{ id: d, address: x, snmp: { version: 3, username: u, context_engine_id: zz } }]`, "hex"},
		{dev(`, sinks: [nope]`), "unknown sink"},
		{dev(`, outputs: [x]`), "a device's outputs were replaced by sinks"},
		{dev(`, profiles: [x]`), "field profiles not found"},
		{dev(`, scalars: []`), "field scalars not found"},
		{dev(`, exclude: [nope]`), `unknown capability "nope"`},
		{dev(`, exclude: [uptime]`), "every capability is excluded"},
		{dev(`, include: { nope: [x] }`), `unknown table "nope"`},
		{dev(`, include: { nope: ["("] }`), "missing closing )"},
		{dev(``) + "\n" + `outputs: [{ name: a, type: "null" }]`, "outputs were replaced by sinks"},
		{dev(``) + "\n" + `sinks: [{ id: a, type: prometheus, url: "http://prom:9090/api/v1/write" }, { id: a, type: prometheus, url: "http://prom:9090/api/v1/write" }]`, "duplicate id"},
	} {
		_, err := parse(t, tc.doc)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\n  err = %v, want containing %q", tc.doc, err, tc.want)
		}
	}
}

func TestCapabilityErrors(t *testing.T) {
	for _, tc := range []struct {
		caps map[string]string
		want string
	}{
		{map[string]string{"e.yaml": ``}, "empty capability"},
		{map[string]string{"e.yaml": `bogus: 1`}, "field bogus not found"},
		{map[string]string{"bad name.yaml": uptime}, "may only contain"},
		{map[string]string{"a.yaml": uptime, "a.yml": uptime}, "defined by both a.yaml and a.yml"},
		{map[string]string{"a.yaml": `detect: [x]` + "\n" + uptime}, "detect: invalid oid"},
		{map[string]string{"a.yaml": `scalars: [{ name: a, oid: x.y }]`}, "invalid oid"},
		{map[string]string{"a.yaml": `scalars: [{ name: a, oid: 1.3, modes: [delta] }]`}, "invalid mode"},
		{map[string]string{"a.yaml": `scalars: [{ name: a, oid: 1.3 }, { name: a, oid: 1.4 }]`}, "duplicate scalar"},
		{map[string]string{"a.yaml": `tables: [{ name: t }]`}, "at least one column"},
		{map[string]string{"a.yaml": `tables: [{ name: t, include: ["("], columns: [{ name: c, oid: 1.3 }] }]`}, "include"},
		{map[string]string{"a.yaml": `tables: [{ name: t, columns: [{ name: c }] }]`}, "oid, hc_oid or formula is required"},
		{map[string]string{"a.yaml": `scalars: [{ name: a }]`}, "exactly one of oid, oids and formula"},
		{map[string]string{"a.yaml": `scalars: [{ name: a, oid: 1.3, oids: [1.4] }]`}, "exactly one of oid, oids and formula"},
		{map[string]string{"a.yaml": `scalars: [{ name: a, oids: [1.3, x] }]`}, `oids: invalid oid "x"`},
		{map[string]string{"a.yaml": `scalars: [{ name: a, formula: "1 +" }]`}, `formula "1 +": at column 4: expected a number`},
		{map[string]string{"a.yaml": `scalars: [{ name: a, formula: "(1" }]`}, `expected ")"`},
		{map[string]string{"a.yaml": `scalars: [{ name: a, formula: "2 % 1" }]`}, `unexpected "%"`},
		{map[string]string{"a.yaml": `scalars: [{ name: a, formula: "1.2.3" }]`}, `invalid number "1.2.3"`},
		{map[string]string{"a.yaml": `scalars: [{ name: a, formula: "a * 2" }]`}, `"a" is not a scalar defined above it`},
		{map[string]string{"a.yaml": `scalars: [{ name: a, formula: "b" }, { name: b, oid: 1.3 }]`}, `"b" is not a scalar defined above it`},
		{map[string]string{"a.yaml": "scalars: [{ name: b, oid: 1.3 }, { name: a, formula: \"b\", modes: [rate] }]"}, "modes cannot be used with formula"},
		{map[string]string{"a.yaml": `tables: [{ name: t, columns: [{ name: c, oid: 1.3, formula: "1" }] }]`}, "formula cannot be used with oid"},
		{map[string]string{"a.yaml": `tables: [{ name: t, columns: [{ name: c, oid: 1.3 }, { name: d, formula: "c / e" }] }]`},
			`"e" is not a column defined above it in this table`},
		{map[string]string{"a.yaml": `tables: [{ name: t, columns: [{ name: d, formula: "2" }] }]`}, "at least one column needs an oid"},
		{map[string]string{"a.yaml": `tables: [{ name: t, columns: [{ name: c, oid: 1.3, hc_oid: 1.4 }] }]`}, "hc_oid requires high_capacity"},
		{map[string]string{"a.yaml": `tables: [{ name: t, high_capacity: { probe: 1.3, speed: s }, columns: [{ name: c, oid: 1.3 }] }]`}, "high_capacity requires a label"},
		{map[string]string{"a.yaml": `
discovery: { columns: { n: 1.3.1 } }
tables: [{ name: t, label: n, high_capacity: { probe: 1.3, speed: s }, columns: [{ name: c, oid: 1.3 }] }]`}, `high_capacity.speed "s" is not a discovery column`},
		// Labels must come from the same capability: another one may not apply.
		{map[string]string{
			"a.yaml": `discovery: { columns: { ifName: 1.3.1 } }`,
			"b.yaml": `tables: [{ name: t, label: ifName, columns: [{ name: c, oid: 1.3 }] }]`,
		}, `label "ifName" is not a discovery column of this capability`},
		{map[string]string{"a.yaml": `scalars: [{ name: x, oid: 1.3 }]`, "b.yaml": `scalars: [{ name: x, oid: 1.4 }]`},
			`scalar "x" is defined by both "a" and "b"`},
		{map[string]string{"a.yaml": `tables: [{ name: x, columns: [{ name: c, oid: 1.3 }] }]`, "b.yaml": `tables: [{ name: x, columns: [{ name: c, oid: 1.4 }] }]`},
			`table "x" is defined by both "a" and "b"`},
		{map[string]string{"a.yaml": `discovery: { scalars: { x: 1.3 } }`, "b.yaml": `discovery: { scalars: { x: 1.4 } }`},
			`discovery scalar "x" has different oids`},
	} {
		_, err := parseWith(t, `devices: []`, tc.caps)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v\n  err = %v, want containing %q", tc.caps, err, tc.want)
		}
	}
	// The same discovery entry may be shared when its OID is the same.
	if _, err := parseWith(t, `devices: []`, map[string]string{
		"a.yaml": `discovery: { columns: { ifName: 1.3.1 } }`,
		"b.yaml": `discovery: { columns: { ifName: .1.3.1 } }`,
	}); err != nil {
		t.Errorf("shared discovery column: %v", err)
	}
}

func TestDisabledDeviceSkipped(t *testing.T) {
	c := mustParse(t, `devices: [{ id: d, address: x, enabled: false }]`)
	if len(c.DeviceSpecs()) != 0 {
		t.Error("disabled device must not be resolved")
	}
}

// vaultDev is a device reading its credentials from Vault with auth.
func vaultDev(auth string) string {
	return `vault: { address: "https://vault:8200", auth: ` + auth + ` }
devices: [{ id: d, address: x, snmp: { vault: true } }]`
}

func TestUnusedCredentialNotValidated(t *testing.T) {
	// Neither the disabled device nor Vault (used by no enabled device) is
	// validated beyond its syntax.
	c := mustParse(t, `
vault: { address: "https://vault:8200", auth: { method: token, token: "${UNSET_VAR_FOR_TEST}" } }
devices:
  - { address: x, enabled: false, snmp: { version: 2c, community: "${UNSET_VAR_FOR_TEST}" } }
  - { address: y, enabled: false, snmp: { vault: true } }
  - { address: z, snmp: { version: 2c, community: c } }
`)
	if len(c.DeviceSpecs()) != 1 {
		t.Errorf("specs = %d, want 1", len(c.DeviceSpecs()))
	}
}

func TestDefaultID(t *testing.T) {
	c := mustParse(t, `
global: { port: 1161 }
devices:
  - { address: 192.0.2.1, snmp: { version: 2c, community: c } }
  - { address: 192.0.2.1, port: 161, snmp: { version: 2c, community: c } }
  - { address: "2001:db8::1", snmp: { version: 2c, community: c } }
  - { address: core-1.example.net, snmp: { version: 2c, community: c } }
  - { id: named, address: 192.0.2.2, snmp: { version: 2c, community: c } }
  # The same agent twice is only valid for two SNMPv3 contexts.
  - { id: vrf-a, address: 192.0.2.3, snmp: { version: 3, username: u, context_name: a } }
  - { id: vrf-b, address: 192.0.2.3, snmp: { version: 3, username: u, context_name: b } }
`)
	var ids []string
	for _, s := range c.DeviceSpecs() {
		ids = append(ids, s.ID)
	}
	want := "[192.0.2.1-1161 192.0.2.1-161 2001_db8__1-1161 core-1.example.net-1161 named vrf-a vrf-b]"
	if fmt.Sprint(ids) != want {
		t.Errorf("ids = %v, want %s", ids, want)
	}
	if c.Devices[0].ID != "192.0.2.1-1161" {
		t.Errorf("Devices[0].ID = %q, want the default id", c.Devices[0].ID)
	}
}

func TestTransportAndWalk(t *testing.T) {
	c := mustParse(t, `
global: { transport: TCP, walk: getnext }
devices:
  - { id: inherit, address: a, snmp: { version: 2c, community: c } }
  - { id: override, address: b, transport: udp, walk: bulk, snmp: { version: 2c, community: c } }
  - { id: v1, address: c, snmp: { version: 1, community: c } }
`)
	got := map[string]string{}
	for _, s := range c.DeviceSpecs() {
		got[s.ID] = s.Transport + "/" + s.Walk
	}
	want := map[string]string{"inherit": "tcp/getnext", "override": "udp/bulk", "v1": "tcp/getnext"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("transport/walk = %v, want %v", got, want)
	}
	// The bulk default does not apply to SNMPv1, which has no GETBULK.
	c = mustParse(t, `devices: [{ id: v1, address: c, snmp: { version: 1, community: c } }]`)
	if w := c.DeviceSpecs()[0].Walk; w != WalkGetNext {
		t.Errorf("v1 walk = %s, want getnext", w)
	}
}

func TestSecretNeverLeaks(t *testing.T) {
	t.Setenv("TEST_COMMUNITY", "super-secret-community")
	c := mustParse(t, `
devices:
  - id: d
    address: x
    snmp: { version: 2c, community: "${TEST_COMMUNITY}" }
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
	_, err := parse(t, `devices: [{ id: d, address: x, snmp: { version: 3, username: u, auth_protocol: MD5, auth_password: leak } }]`)
	if err == nil || strings.Contains(err.Error(), "leak") {
		t.Errorf("err = %v", err)
	}
}

// writeConfig writes a main file and its conf.d files (name -> content)
// next to a capabilities.d holding the uptime capability, and returns the
// path of the main file.
func writeConfig(t *testing.T, main string, include map[string]string) string {
	t.Helper()
	dir := writeCaps(t, map[string]string{"uptime.yaml": uptime})
	if include != nil {
		if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, doc := range include {
		if err := os.WriteFile(filepath.Join(dir, "conf.d", name), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "snmp-poller.yaml")
	if err := os.WriteFile(path, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIncludeDir(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "from-env")
	path := writeConfig(t, `
global: { poll_interval: 30s }
sinks: [{ id: main, type: prometheus, url: "http://prom:9090/api/v1/write" }]
devices:
  - { id: from-main, address: 192.0.2.1, snmp: { version: 2c, community: c } }
`, map[string]string{
		"20-devices.yaml": `
devices:
  - address: 192.0.2.10
    snmp: { version: 2c, community: public }
  - id: legacy-ups
    address: 192.0.2.11
    port: 1161
    transport: tcp
    sinks: [extra]
    snmp: { version: 1, community: "${SNMP_COMMUNITY}" }
  - id: core-1
    address: 192.0.2.12
    walk: getnext
    poll_interval: 10s
    snmp:
      version: 3
      username: poller
      security_level: authPriv
      auth_protocol: SHA256
      auth_password: change-me-auth
      priv_protocol: AES
`,
		"10-vault.yml": `
vault:
  address: https://vault.example.net:8200
  auth: { method: approle, role_id: snmp-poller, secret_id: change-me }
devices:
  - { id: edge-1, address: 192.0.2.13, snmp: { vault: true } }
  - { id: edge-2, address: 192.0.2.14, snmp: { vault: network/edge-v3 } }
`,
		"30-sinks.yaml":     `sinks: [{ id: extra, type: influxdb, url: "http://influx:8181", database: snmp }]`,
		"40-logging.yaml":   `logging: { level: debug }`,
		"50-empty.yaml":     "# nothing yet\n",
		"devices.yaml.bak":  "not: yaml: [",                       // not *.yaml: ignored
		".#lock.yaml":       "not: yaml: [",                       // hidden: ignored
		"devices.yaml.orig": `devices: [{ address: 192.0.2.99 }]`, // ignored
	})
	if err := os.Mkdir(filepath.Join(filepath.Dir(path), "conf.d", "sub.yaml"), 0o755); err != nil {
		t.Fatal(err) // a directory: ignored
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	wantFiles := []string{path, filepath.Join(dir, "conf.d", "10-vault.yml"), filepath.Join(dir, "conf.d", "20-devices.yaml"),
		filepath.Join(dir, "conf.d", "30-sinks.yaml"), filepath.Join(dir, "conf.d", "40-logging.yaml"),
		filepath.Join(dir, "conf.d", "50-empty.yaml")}
	if !slices.Equal(c.Files(), wantFiles) {
		t.Errorf("files = %q\nwant %q", c.Files(), wantFiles)
	}
	// Main file first, then the files in name order.
	var got []string
	for _, s := range c.DeviceSpecs() {
		got = append(got, fmt.Sprintf("%s %s %s %s %v %s %v", s.ID, s.SNMP.Version, s.Transport, s.Walk,
			s.PollInterval, s.VaultPath, s.Sinks))
	}
	want := []string{
		"from-main 2c udp bulk 30s  [main extra]",
		"edge-1  udp bulk 30s snmp-poller/edge-1 [main extra]",
		"edge-2  udp bulk 30s network/edge-v3 [main extra]",
		"192.0.2.10-161 2c udp bulk 30s  [main extra]",
		"legacy-ups 1 tcp getnext 30s  [extra]",
		"core-1 3 udp getnext 10s  [main extra]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("devices:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if s := c.DeviceSpecs()[5].SNMP; s.SecurityLevel != AuthPriv || s.PrivPassword.Reveal() != "change-me-auth" {
		t.Errorf("core-1 snmp = %+v", s)
	}
	if v := c.DeviceSpecs()[4].SNMP.Community.Reveal(); v != "from-env" {
		t.Errorf("legacy-ups community = %q", v)
	}
	if a := c.Vault.Auth; a.Method != VaultAppRole || a.SecretID.Reveal() != "change-me" {
		t.Errorf("vault auth = %+v", a)
	}
	if c.Logging.Level != "debug" || !*c.Logging.Console.Enabled {
		t.Errorf("logging = %+v", c.Logging)
	}

	// No include directory: only the main file (the default is optional).
	c = mustParse(t, minimalDevice)
	if len(c.Files()) != 0 || len(c.DeviceSpecs()) != 1 {
		t.Errorf("files = %v, devices = %d", c.Files(), len(c.DeviceSpecs()))
	}
}

func TestIncludeDirErrors(t *testing.T) {
	dev := func(id, addr string) string {
		return "devices: [{ id: " + id + ", address: " + addr + ", snmp: { version: 2c, community: c } }]\n"
	}
	for _, tc := range []struct {
		name    string
		main    string
		include map[string]string
		want    []string
	}{
		{"global in an included file", "", map[string]string{"a.yaml": "global: { threads: 2 }"},
			[]string{"conf.d/a.yaml: line 1: global is only allowed in the main configuration file"}},
		{"logging twice", "logging: { level: debug }", map[string]string{"a.yaml": "logging: { level: warn }"},
			[]string{"conf.d/a.yaml: logging is already defined in ", "snmp-poller.yaml"}},
		{"vault twice", "", map[string]string{
			"a.yaml": "vault: { address: https://v:8200, auth: { method: token, token: t } }",
			"b.yaml": "vault: { address: https://v:8200, auth: { method: token, token: t } }"},
			[]string{"conf.d/b.yaml: vault is already defined in ", "conf.d/a.yaml"}},
		{"duplicate id across files", dev("r1", "192.0.2.1"), map[string]string{"a.yaml": dev("r1", "192.0.2.2")},
			[]string{`conf.d/a.yaml: device "r1": duplicate id (also `, `snmp-poller.yaml devices[0])`}},
		{"duplicate address across files", "", map[string]string{"a.yaml": dev("r1", "192.0.2.1"), "b.yaml": dev("r2", "192.0.2.1")},
			[]string{`conf.d/b.yaml: device "r2": address 192.0.2.1 port 161 is already used by device "r1"`}},
		{"device error names its file", "", map[string]string{"a.yaml": "devices: [{ id: d }]"},
			[]string{"conf.d/a.yaml: devices[0]: address is required"}},
		{"duplicate sink across files", `sinks: [{ id: o, type: prometheus, url: "http://prom:9090/api/v1/write" }]`, map[string]string{"a.yaml": `sinks: [{ id: o, type: prometheus, url: "http://prom:9090/api/v1/write" }]`},
			[]string{`conf.d/a.yaml: sinks[0]: duplicate id "o" (also in `, "snmp-poller.yaml)"}},
		{"unknown key names its file and line", "", map[string]string{"a.yaml": "devices: []\ndevice: []"},
			[]string{"conf.d/a.yaml: yaml: unmarshal errors:", "line 2: field device not found"}},
		{"capability in conf.d", "", map[string]string{"system.yaml": uptime},
			[]string{"conf.d/system.yaml: this is a capability, not a configuration file"}},
		{"conf_dir renamed", "global: { conf_dir: conf.d }", nil,
			[]string{"snmp-poller.yaml: line 1: global.conf_dir was renamed global.capabilities_dir"}},
		{"explicit include_dir missing", "global: { include_dir: nope }", nil,
			[]string{"snmp-poller.yaml: global.include_dir: open ", "nope: no such file or directory"}},
		{"same directories", "global: { include_dir: capabilities.d }", nil,
			[]string{"global.include_dir and global.capabilities_dir must be different directories"}},
		{"several errors at once", "", map[string]string{"a.yaml": "devices: [{ id: d }]", "b.yaml": "global: {}"},
			[]string{"conf.d/b.yaml: line 1: global is only allowed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.main, tc.include))
			for _, w := range tc.want {
				if err == nil || !strings.Contains(filepath.ToSlash(err.Error()), w) {
					t.Errorf("err = %v, want %q", err, w)
				}
			}
		})
	}
}
