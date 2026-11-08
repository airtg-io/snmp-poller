package config

import (
	"log/slog"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Secret holds a credential (community string, passphrase, ...).
// It never reveals its value when printed, logged or marshaled.
// Use Reveal to obtain the clear-text value when talking to a device.
type Secret struct {
	value string
}

const redacted = "******"

// NewSecret wraps a clear-text value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal returns the clear-text value. Only call it to hand the value to the SNMP stack.
func (s Secret) Reveal() string { return s.value }

// IsSet reports whether the secret is non-empty.
func (s Secret) IsSet() bool { return s.value != "" }

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
	if s.value == "" {
		return ""
	}
	return redacted
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// UnmarshalYAML implements yaml.Unmarshaler. ${VAR} references are expanded
// from the environment so secrets do not have to live in the config file.
func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	var raw string
	if err := n.Decode(&raw); err != nil {
		return err
	}
	s.value = envRef.ReplaceAllStringFunc(raw, func(m string) string {
		return os.Getenv(envRef.FindStringSubmatch(m)[1])
	})
	return nil
}
