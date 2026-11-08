package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Vault auth methods.
const (
	VaultToken      = "token"
	VaultAppRole    = "approle"
	VaultUserpass   = "userpass"
	VaultKubernetes = "kubernetes"
)

// DefaultKubernetesJWT is the service account token mounted in every pod.
const DefaultKubernetesJWT = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Vault configures HashiCorp Vault, an external store for device
// credentials. Devices opt in with `snmp: { vault: ... }`; their credentials
// are read from a KV secret at every discovery.
type Vault struct {
	Address   string `yaml:"address"`
	Namespace string `yaml:"namespace"` // Vault Enterprise namespace
	// Mount is the KV secrets engine mount path, KVVersion its version.
	Mount     string `yaml:"mount"`
	KVVersion int    `yaml:"kv_version"`
	// Prefix is the parent path of the default secret of each device:
	// <prefix>/<device id>.
	Prefix        string        `yaml:"prefix"`
	Timeout       time.Duration `yaml:"timeout"`
	CACert        string        `yaml:"ca_cert"`
	TLSSkipVerify bool          `yaml:"tls_skip_verify"`
	Auth          VaultAuth     `yaml:"auth"`
}

// VaultAuth selects how the poller logs in to Vault. Secrets are encrypted
// in the configuration file like device credentials.
type VaultAuth struct {
	Method string `yaml:"method"`
	// Mount is the auth method mount path; it defaults to the method name.
	Mount    string `yaml:"mount"`
	Token    Secret `yaml:"token"`     // token
	RoleID   string `yaml:"role_id"`   // approle
	SecretID Secret `yaml:"secret_id"` // approle
	Username string `yaml:"username"`  // userpass
	Password Secret `yaml:"password"`  // userpass
	Role     string `yaml:"role"`      // kubernetes
	JWTFile  string `yaml:"jwt_file"`  // kubernetes
}

// VaultRef is a device's `snmp.vault` setting: `true` reads the credentials
// from <vault.prefix>/<device id>, a string from that path (relative to the
// KV mount), `false` or absent disables Vault.
type VaultRef struct {
	Enabled bool
	Path    string
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *VaultRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: vault must be true, false or a secret path", n.Line)
	}
	if n.ShortTag() == "!!bool" {
		var b bool
		if err := n.Decode(&b); err != nil {
			return err
		}
		*v = VaultRef{Enabled: b}
		return nil
	}
	p := strings.Trim(n.Value, "/")
	if p == "" {
		return fmt.Errorf("line %d: vault path is empty", n.Line)
	}
	*v = VaultRef{Enabled: true, Path: p}
	return nil
}

func (v *Vault) applyDefaults() {
	if v.Mount == "" {
		v.Mount = "secret"
	}
	v.Mount = strings.Trim(v.Mount, "/")
	if v.KVVersion == 0 {
		v.KVVersion = 2
	}
	if v.Prefix == "" {
		v.Prefix = "snmp-poller"
	}
	v.Prefix = strings.Trim(v.Prefix, "/")
	if v.Timeout == 0 {
		v.Timeout = 10 * time.Second
	}
	a := &v.Auth
	a.Method = strings.ToLower(a.Method)
	if a.Mount == "" {
		a.Mount = a.Method
	}
	a.Mount = strings.Trim(a.Mount, "/")
	if a.Method == VaultKubernetes && a.JWTFile == "" {
		a.JWTFile = DefaultKubernetesJWT
	}
}

// validate checks the vault block. Credentials are only required when used
// (used = an enabled device reads its credentials from Vault).
func (v *Vault) validate(used bool) error {
	u, err := url.Parse(v.Address)
	switch {
	case v.Address == "":
		return errors.New("vault.address is required")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return fmt.Errorf("vault.address %q must be an http:// or https:// URL", v.Address)
	case v.KVVersion != 1 && v.KVVersion != 2:
		return errors.New("vault.kv_version must be 1 or 2")
	case v.Timeout < 0:
		return errors.New("vault.timeout must be > 0")
	}
	a := v.Auth
	methods := []string{VaultToken, VaultAppRole, VaultUserpass, VaultKubernetes}
	if !slices.Contains(methods, a.Method) {
		return fmt.Errorf("vault.auth.method %q: must be %s", a.Method, strings.Join(methods, ", "))
	}
	if !used {
		return nil
	}
	var missing string
	switch a.Method {
	case VaultToken:
		if !a.Token.IsSet() {
			missing = "token"
		}
	case VaultAppRole:
		if a.RoleID == "" {
			missing = "role_id"
		} else if !a.SecretID.IsSet() {
			missing = "secret_id"
		}
	case VaultUserpass:
		if a.Username == "" {
			missing = "username"
		} else if !a.Password.IsSet() {
			missing = "password"
		}
	case VaultKubernetes:
		if a.Role == "" {
			missing = "role"
		}
	}
	if missing != "" {
		return fmt.Errorf("vault.auth: method %s requires %s", a.Method, missing)
	}
	return nil
}

// vaultKeys are the keys a device's Vault secret may hold, each overriding
// the same key of the device's snmp block.
var vaultKeys = map[string]func(*SNMP, string){
	"version":           func(s *SNMP, v string) { s.Version = v },
	"community":         func(s *SNMP, v string) { s.Community = NewSecret(v) },
	"username":          func(s *SNMP, v string) { s.Username = v },
	"security_level":    func(s *SNMP, v string) { s.SecurityLevel = v },
	"auth_protocol":     func(s *SNMP, v string) { s.AuthProtocol = v },
	"auth_password":     func(s *SNMP, v string) { s.AuthPassword = NewSecret(v) },
	"priv_protocol":     func(s *SNMP, v string) { s.PrivProtocol = v },
	"priv_password":     func(s *SNMP, v string) { s.PrivPassword = NewSecret(v) },
	"context_name":      func(s *SNMP, v string) { s.ContextName = v },
	"context_engine_id": func(s *SNMP, v string) { s.ContextEngineID = v },
}

// VaultKeys returns the keys a Vault secret may hold, sorted.
func VaultKeys() []string { return sortedKeys(vaultKeys) }

// WithVaultSecret returns a copy of the device spec whose SNMP settings are
// the device's snmp block overridden by the keys of its Vault secret, then
// normalized and validated like a static configuration. Errors never
// include secret values.
func (s *DeviceSpec) WithVaultSecret(secret map[string]string) (*DeviceSpec, error) {
	out := *s
	for _, k := range sortedKeys(secret) {
		set, ok := vaultKeys[k]
		if !ok {
			return nil, fmt.Errorf("unknown key %q (allowed: %s)", k, strings.Join(VaultKeys(), ", "))
		}
		set(&out.SNMP, secret[k])
	}
	if err := out.finishSNMP(); err != nil {
		return nil, err
	}
	return &out, nil
}
