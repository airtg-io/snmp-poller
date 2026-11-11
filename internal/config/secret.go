package config

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Secret holds a credential (community string, password, Vault token, ...).
// It never reveals its value when printed, logged or marshaled.
// Use Reveal to obtain the clear-text value when talking to a device.
//
// In the configuration file a secret is written in one of three forms:
//   - clear text, encrypted in place by Config.Seal on startup;
//   - encrypted, ~~HEX~~ (see crypt.go), decrypted with <data_dir>/key.dat;
//   - a ${ENV_VAR} reference, expanded from the environment and left as is.
type Secret struct {
	value string
	src   secretSource
}

// secretSource is where and how a secret is written in the file.
type secretSource struct {
	raw       string // as written, before expansion or decryption
	line, col int    // 1-based position of the YAML scalar
	style     yaml.Style
}

const redacted = "******"

// NewSecret wraps a clear-text value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal returns the clear-text value. Only call it to hand the value to the SNMP stack.
func (s Secret) Reveal() string { return s.value }

// IsSet reports whether the secret is non-empty.
func (s Secret) IsSet() bool { return s.value != "" }

// written reports whether the secret is written in the file, before or
// after its resolution.
func (s Secret) written() bool { return s.value != "" || s.src.raw != "" }

func (s Secret) String() string   { return s.mask() }
func (s Secret) GoString() string { return s.mask() }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.mask()) }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + s.mask() + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.mask()), nil }

// MarshalYAML implements yaml.Marshaler.
func (s Secret) MarshalYAML() (any, error) { return s.mask(), nil }

func (s Secret) mask() string {
	if s.value == "" && s.src.raw == "" {
		return ""
	}
	return redacted
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// UnmarshalYAML implements yaml.Unmarshaler. It only records the value as
// written and its position: Config.resolveSecrets expands, decrypts and
// validates it once the key location (data_dir) is known.
func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	var raw string
	if err := n.Decode(&raw); err != nil {
		return err
	}
	*s = Secret{src: secretSource{raw: raw, line: n.Line, col: n.Column, style: n.Style}}
	return nil
}

func (s *Secret) isEnv() bool       { return envRef.MatchString(s.src.raw) }
func (s *Secret) isEncrypted() bool { return encryptedPattern.MatchString(s.src.raw) }

// isClear reports whether the secret is written in clear text in the file,
// and so must be encrypted by Seal.
func (s *Secret) isClear() bool { return s.src.raw != "" && !s.isEnv() && !s.isEncrypted() }

// resolve sets the clear-text value from the written form. key is only
// called for encrypted secrets.
func (s *Secret) resolve(key func() ([]byte, error)) error {
	switch {
	case s.isEnv():
		s.value = envRef.ReplaceAllStringFunc(s.src.raw, func(m string) string {
			return os.Getenv(envRef.FindStringSubmatch(m)[1])
		})
	case s.isEncrypted():
		k, err := key()
		if err != nil {
			return err
		}
		v, err := decrypt(k, s.src.raw)
		if err != nil {
			return fmt.Errorf("line %d: %w", s.src.line, err)
		}
		s.value = v
	default:
		s.value = s.src.raw
	}
	return nil
}
