package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sealFixture writes a configuration file using every way of writing a
// credential, with comments, in a temporary directory.
func sealFixture(t *testing.T) (path, dataDir string) {
	t.Helper()
	t.Setenv("SEAL_TEST_COMMUNITY", "from-env")
	dir := writeCaps(t, map[string]string{"uptime.yaml": uptime})
	dataDir = filepath.Join(dir, "data")
	path = filepath.Join(dir, "snmp-poller.yaml")
	doc := `# Main configuration - comments survive.
global:
  data_dir: ` + dataDir + `   # temp

vault:
  address: https://vault:8200
  auth: { method: approle, role_id: r, secret_id: "s3cr3t-id" }

devices:
  - address: 10.0.0.1 # plain
    snmp: &shared
      version: 2c
      community: plain-community   # trailing comment
  - address: 10.0.0.2
    snmp: *shared  # alias: same scalar, encrypted once
  - { address: 10.0.0.3, snmp: { version: 2c, community: 'single ''quoted''' } }
  - address: 10.0.0.4
    snmp:
      version: 3
      username: üser
      auth_protocol: SHA
      auth_password: "dqu\"oted-pass"
      priv_protocol: AES
      priv_password: ~~not-hex~~   # not hex: a clear-text password
  - address: 10.0.0.5
    snmp: { version: 2c, community: "${SEAL_TEST_COMMUNITY}" }
  - address: 10.0.0.6
    enabled: false
    snmp: { version: 2c, community: disabled-too }
`
	if err := os.WriteFile(path, []byte(doc), 0o640); err != nil {
		t.Fatal(err)
	}
	return path, dataDir
}

func load(t *testing.T, path string) *Config {
	t.Helper()
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSeal(t *testing.T) {
	path, dataDir := sealFixture(t)
	before, _ := os.ReadFile(path)

	c := load(t, path)
	res, err := c.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if !res.KeyCreated || res.Encrypted != 6 || res.KeyPath != filepath.Join(dataDir, KeyFile) {
		t.Errorf("seal = %+v, want a new key and 6 encrypted values", res)
	}
	key, err := os.Stat(res.KeyPath)
	if err != nil || key.Size() != 32 || key.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", key, err)
	}

	after, _ := os.ReadFile(path)
	text := string(after)
	for _, clear := range []string{"plain-community", "quoted", "s3cr3t-id", "dqu", "not-hex", "disabled-too"} {
		if strings.Contains(text, clear) {
			t.Errorf("%q still in clear text:\n%s", clear, text)
		}
	}
	if n := len(regexp.MustCompile(`~~(?:[0-9A-F]{2})+~~`).FindAllString(text, -1)); n != 6 {
		t.Errorf("found %d encrypted values, want 6:\n%s", n, text)
	}
	// Everything but the values is kept byte for byte.
	strip := regexp.MustCompile(`plain-community|'single ''quoted'''|"s3cr3t-id"|"dqu\\"oted-pass"|~~not-hex~~|disabled-too|~~[0-9A-F]+~~`)
	if strip.ReplaceAllString(string(before), "X") != strip.ReplaceAllString(text, "X") {
		t.Errorf("layout changed:\n--- before\n%s\n--- after\n%s", before, text)
	}
	if !strings.Contains(text, "${SEAL_TEST_COMMUNITY}") || !strings.Contains(text, "# trailing comment") {
		t.Errorf("env reference or comment lost:\n%s", text)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("file mode = %v, want kept", info.Mode())
	}

	// The sealed file reads back to the same credentials.
	c2 := load(t, path)
	if got, want := c2.secretValues(), c.secretValues(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("read back %q, want %q", got, want)
	}
	if v := c2.DeviceSpecs()[3].SNMP.PrivPassword.Reveal(); v != "~~not-hex~~" {
		t.Errorf("priv_password = %q", v)
	}
	if v := c2.Vault.Auth.SecretID.Reveal(); v != "s3cr3t-id" {
		t.Errorf("vault secret_id = %q", v)
	}

	// Sealing again changes nothing.
	res, err = c2.Seal()
	if err != nil || res.KeyCreated || res.Encrypted != 0 {
		t.Errorf("second seal = %+v, %v", res, err)
	}
	if again, _ := os.ReadFile(path); string(again) != text {
		t.Error("second seal rewrote the file")
	}
}

func TestSealKeyErrors(t *testing.T) {
	path, dataDir := sealFixture(t)
	if _, err := load(t, path).Seal(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dataDir, KeyFile)

	os.Rename(keyPath, keyPath+".bak")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "credentials are encrypted but the key "+keyPath+" does not exist") {
		t.Errorf("missing key: %v", err)
	}
	os.WriteFile(keyPath, []byte("short"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Errorf("short key: %v", err)
	}
	os.WriteFile(keyPath, make([]byte, 32), 0o600)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "devices[0].snmp.community: line 13: cannot decrypt credential: it was encrypted with another key") {
		t.Errorf("wrong key: %v", err)
	}
}

func TestSealReadOnlyFile(t *testing.T) {
	path, _ := sealFixture(t)
	before, _ := os.ReadFile(path)
	c := load(t, path)
	dir := filepath.Dir(path)
	os.Chmod(dir, 0o555)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if _, err := c.Seal(); err == nil {
		t.Fatal("expected an error writing to a read-only directory")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("file changed")
	}
}

func TestSealFollowsSymlink(t *testing.T) {
	path, _ := sealFixture(t)
	link := filepath.Join(filepath.Dir(path), "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := load(t, link).Seal(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink replaced by a file")
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "plain-community") {
		t.Error("target not sealed")
	}
}

func TestSealUnsupportedScalar(t *testing.T) {
	dir := writeCaps(t, map[string]string{"uptime.yaml": uptime})
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte(`global: { data_dir: `+filepath.Join(dir, "data")+` }
devices:
  - address: x
    snmp:
      version: 2c
      community: |
        block-scalar
`), 0o644)
	before, _ := os.ReadFile(path)
	_, err := load(t, path).Seal()
	if err == nil || !strings.Contains(err.Error(), "devices[0].snmp.community (line 6): cannot encrypt in place") {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(err.Error(), "block-scalar") {
		t.Error("error leaks the credential")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("file changed")
	}
}

func TestEncryptedPattern(t *testing.T) {
	for s, want := range map[string]bool{
		"~~ABCE09CBBAEEEE90~~": true,
		"~~abcdef~~":           true,
		"~~ABC~~":              false, // odd number of digits
		"~~~~":                 false,
		"~~GG~~":               false,
		"ABCD":                 false,
		" ~~AB~~":              false,
	} {
		if got := encryptedPattern.MatchString(s); got != want {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}
	key := make([]byte, 32)
	enc := encrypt(key, "secret")
	if !encryptedPattern.MatchString(enc) || enc == encrypt(key, "secret") {
		t.Errorf("encrypt must match the pattern and use a random nonce: %s", enc)
	}
	if v, err := decrypt(key, strings.ToLower(enc)); err != nil || v != "secret" {
		t.Errorf("decrypt (lower case) = %q, %v", v, err)
	}
	if _, err := decrypt(key, "~~ABCD~~"); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated: %v", err)
	}
}

// A value encrypted by hand (snmp-poller -encrypt) is read back by the
// poller with the same key.
func TestEncryptValue(t *testing.T) {
	dir := writeCaps(t, map[string]string{"uptime.yaml": uptime})
	dataDir := filepath.Join(dir, "data")
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte("global: { data_dir: "+dataDir+" }\n"), 0o644)

	got, err := DataDir(path)
	if err != nil || got != dataDir {
		t.Fatalf("DataDir = %q, %v", got, err)
	}
	enc, created, err := EncryptValue(KeyPath(got), "hand-made secret")
	if err != nil || !created || !encryptedPattern.MatchString(enc) {
		t.Fatalf("EncryptValue = %q, %v, %v", enc, created, err)
	}
	if _, created, _ := EncryptValue(KeyPath(got), "x"); created {
		t.Error("existing key must be reused")
	}
	os.WriteFile(path, []byte("global: { data_dir: "+dataDir+" }\ndevices: [{ address: x, snmp: { version: 2c, community: "+enc+" } }]\n"), 0o644)
	if v := load(t, path).DeviceSpecs()[0].SNMP.Community.Reveal(); v != "hand-made secret" {
		t.Errorf("read back %q", v)
	}
	if _, _, err := EncryptValue(KeyPath(got), ""); err == nil {
		t.Error("empty value must be refused")
	}

	os.WriteFile(path, []byte("logging: {}\n"), 0o644)
	if got, _ := DataDir(path); got != "data" {
		t.Errorf("default DataDir = %q", got)
	}
}
