package config

import (
	"os"
	"strings"
	"testing"
)

func TestVaultDevice(t *testing.T) {
	c := mustParse(t, `
vault:
  address: https://vault.example.net:8200/
  prefix: /network/snmp/
  auth: { method: kubernetes, role: poller }
devices:
  - { id: dflt, address: a, snmp: { vault: true } }
  - { id: path, address: b, walk: bulk, snmp: { version: 3, vault: /core/v3/ } }
  - { id: off, address: c, snmp: { version: 2c, community: c, vault: false } }
`)
	v := c.Vault
	if v.Mount != "secret" || v.KVVersion != 2 || v.Prefix != "network/snmp" || v.Auth.Mount != "kubernetes" ||
		v.Auth.JWTFile != DefaultKubernetesJWT || v.Timeout.Seconds() != 10 {
		t.Errorf("vault defaults: %+v", v)
	}
	specs := c.DeviceSpecs()
	for i, want := range []string{"network/snmp/dflt", "core/v3", ""} {
		if specs[i].VaultPath != want {
			t.Errorf("%s: vault path = %q, want %q", specs[i].ID, specs[i].VaultPath, want)
		}
	}

	// The secret overrides the snmp block, then everything is validated.
	s, err := specs[1].WithVaultSecret(map[string]string{
		"username": "poller", "auth_protocol": "sha", "auth_password": "auth-pass", "priv_protocol": "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.SNMP.Version != Version3 || s.SNMP.SecurityLevel != AuthPriv || s.SNMP.AuthProtocol != "SHA" ||
		s.SNMP.PrivPassword.Reveal() != "auth-pass" || s.Walk != WalkBulk {
		t.Errorf("merged = %+v", s.SNMP)
	}
	if specs[1].SNMP.Username != "" {
		t.Error("WithVaultSecret modified the device spec")
	}

	// SNMPv1 from Vault: the inherited bulk default becomes getnext, but an
	// explicit walk: bulk is an error.
	if s, err := specs[0].WithVaultSecret(map[string]string{"version": "1", "community": "c"}); err != nil || s.Walk != WalkGetNext {
		t.Errorf("v1 from vault: %+v, %v", s, err)
	}
	for secret, want := range map[string]string{
		"version=1,community=c":                             "bulk is not available in SNMPv1",
		"username=u,auth_protocol=MD5,auth_password=leaked": "auth_password must be at least 8",
		"user=u":     `unknown key "user" (allowed: auth_password, auth_protocol, community, context_engine_id`,
		"vault=true": `unknown key "vault"`,
	} {
		m := map[string]string{}
		for _, kv := range strings.Split(secret, ",") {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		_, err := specs[1].WithVaultSecret(m)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", secret, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "leaked") {
			t.Errorf("error leaks a secret: %v", err)
		}
	}
}

// Every example device of the shipped configuration is valid once enabled.
func TestDefaultConfigExamples(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "from-env")
	data, err := os.ReadFile(repoPath(DefaultPath))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(data), "enabled: false", "enabled: true")
	c, err := Parse(strings.NewReader(doc), repoPath("etc"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range c.DeviceSpecs() {
		got[s.ID] = strings.Join([]string{s.SNMP.Version, s.Transport, s.Walk, s.VaultPath}, " ")
	}
	want := map[string]string{
		"192.0.2.10-161": "2c udp bulk ",
		"legacy-ups":     "1 tcp getnext ",
		"core-1":         "3 udp getnext ",
		"edge-1":         " udp bulk snmp-poller/edge-1",
		"edge-2":         " udp bulk network/edge-v3",
	}
	if len(got) != len(want) {
		t.Errorf("devices = %v", got)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %q, want %q", id, got[id], w)
		}
	}
	if s := c.DeviceSpecs()[2].SNMP; s.SecurityLevel != AuthPriv || s.AuthProtocol != "SHA256" || s.PrivProtocol != "AES" {
		t.Errorf("core-1 snmp = %+v", s)
	}
	if a := c.Vault.Auth; a.Method != VaultAppRole || a.RoleID == "" || !a.SecretID.IsSet() {
		t.Errorf("vault auth = %+v", a)
	}
}
