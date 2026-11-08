// Package config defines the YAML configuration schema of the poller, its
// defaults, validation, credential encryption, and the resolution of each
// device into a flat specification.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the configuration file used when none is given.
const DefaultPath = "etc/snmp-poller.yaml"

// Config is the root of the YAML document.
type Config struct {
	Global  Global   `yaml:"global"`
	Logging Logging  `yaml:"logging"`
	Outputs []Output `yaml:"outputs"`
	Vault   *Vault   `yaml:"vault"`
	Devices []Device `yaml:"devices"`

	capabilities []*Capability
	specs        []DeviceSpec

	path   string // file read by Load, rewritten by Seal
	source []byte
}

// Global holds process-wide settings and the defaults inherited by devices.
type Global struct {
	Threads           int           `yaml:"threads"`
	PollInterval      time.Duration `yaml:"poll_interval"`
	DiscoveryInterval time.Duration `yaml:"discovery_interval"`
	Timeout           time.Duration `yaml:"timeout"`
	Retries           *int          `yaml:"retries"`
	MaxOIDsPerRequest int           `yaml:"max_oids_per_request"`
	MaxRepetitions    uint32        `yaml:"max_repetitions"`
	Port              uint16        `yaml:"port"`
	Transport         string        `yaml:"transport"`
	Walk              string        `yaml:"walk"`
	DataDir           string        `yaml:"data_dir"`
	ConfDir           string        `yaml:"conf_dir"`
	StatsInterval     time.Duration `yaml:"stats_interval"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
}

// Logging configures the console and rotating file log sinks. Records are
// always text (logfmt) with RFC 3339 timestamps that carry their time zone.
type Logging struct {
	Level string `yaml:"level"`
	// LocalTime selects the local time zone for timestamps in records and in
	// rotated file names. The default is UTC.
	LocalTime *bool      `yaml:"local_time"`
	Console   ConsoleLog `yaml:"console"`
	File      FileLog    `yaml:"file"`
}

// ConsoleLog configures logging to stderr.
type ConsoleLog struct {
	Enabled *bool `yaml:"enabled"`
}

// FileLog configures logging to an automatically rotated file.
type FileLog struct {
	Enabled    *bool  `yaml:"enabled"`
	Path       string `yaml:"path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups *int   `yaml:"max_backups"`
	MaxAgeDays *int   `yaml:"max_age_days"`
	Compress   *bool  `yaml:"compress"`
}

// Output declares one destination for polled samples.
// Type-specific settings are kept in Options.
type Output struct {
	Name    string         `yaml:"name"`
	Type    string         `yaml:"type"`
	Options map[string]any `yaml:",inline"`
}

// SNMP is a device's `snmp:` block: version and credentials. v1/v2c use a
// community, v3 a username, a security level and the auth/priv protocols
// and passwords. Credentials may instead (or also) come from Vault.
type SNMP struct {
	Version       string `yaml:"version"`
	Community     Secret `yaml:"community"`
	Username      string `yaml:"username"`
	SecurityLevel string `yaml:"security_level"`
	AuthProtocol  string `yaml:"auth_protocol"`
	AuthPassword  Secret `yaml:"auth_password"`
	PrivProtocol  string `yaml:"priv_protocol"`
	// PrivPassword defaults to AuthPassword, like net-snmp's createUser.
	PrivPassword    Secret   `yaml:"priv_password"`
	ContextName     string   `yaml:"context_name"`
	ContextEngineID string   `yaml:"context_engine_id"`
	Vault           VaultRef `yaml:"vault"`
}

// Device is one SNMP agent to poll.
type Device struct {
	// ID defaults to <address>-<port>.
	ID        string `yaml:"id"`
	Address   string `yaml:"address"`
	Port      uint16 `yaml:"port"`
	Transport string `yaml:"transport"`
	Walk      string `yaml:"walk"`
	Enabled   *bool  `yaml:"enabled"`
	SNMP      *SNMP  `yaml:"snmp"`
	// Exclude lists capabilities never applied to this device, even when
	// detected. Every other capability applies when detected.
	Exclude []string `yaml:"exclude"`
	// Include overrides the include patterns of tables, by table name.
	Include           map[string][]string `yaml:"include"`
	PollInterval      time.Duration       `yaml:"poll_interval"`
	DiscoveryInterval time.Duration       `yaml:"discovery_interval"`
	Timeout           time.Duration       `yaml:"timeout"`
	Retries           *int                `yaml:"retries"`
	MaxOIDsPerRequest int                 `yaml:"max_oids_per_request"`
	MaxRepetitions    uint32              `yaml:"max_repetitions"`
	Outputs           []string            `yaml:"outputs"`
	Trace             bool                `yaml:"trace"`
}

// Load reads, defaults and validates the configuration file at path and the
// capabilities directory it refers to. A relative global.conf_dir is
// resolved against the directory of path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := Parse(f, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.path = path
	return cfg, nil
}

// Parse decodes, defaults and validates a configuration document. A
// relative global.conf_dir is resolved against baseDir.
func Parse(r io.Reader, baseDir string) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	cfg := Config{source: data}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.resolveSecrets(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.Global.ConfDir) {
		cfg.Global.ConfDir = filepath.Join(baseDir, cfg.Global.ConfDir)
	}
	cfg.capabilities, err = LoadCapabilities(cfg.Global.ConfDir)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func ptr[T any](v T) *T { return &v }

func (c *Config) applyDefaults() {
	g := &c.Global
	if g.Threads == 0 {
		g.Threads = 250
	}
	if g.PollInterval == 0 {
		g.PollInterval = time.Minute
	}
	if g.DiscoveryInterval == 0 {
		g.DiscoveryInterval = time.Hour
	}
	if g.Timeout == 0 {
		g.Timeout = 5 * time.Second
	}
	if g.Retries == nil {
		g.Retries = ptr(1)
	}
	if g.MaxOIDsPerRequest == 0 {
		g.MaxOIDsPerRequest = 30
	}
	if g.MaxRepetitions == 0 {
		g.MaxRepetitions = 25
	}
	if g.Port == 0 {
		g.Port = 161
	}
	if g.Transport == "" {
		g.Transport = TransportUDP
	}
	if g.Walk == "" {
		g.Walk = WalkBulk
	}
	if g.DataDir == "" {
		g.DataDir = "data"
	}
	if g.ConfDir == "" {
		g.ConfDir = "conf.d"
	}
	if g.StatsInterval == 0 {
		g.StatsInterval = time.Minute
	}
	if g.ShutdownTimeout == 0 {
		g.ShutdownTimeout = 30 * time.Second
	}

	l := &c.Logging
	if l.Level == "" {
		l.Level = "info"
	}
	if l.Console.Enabled == nil {
		l.Console.Enabled = ptr(true)
	}
	if l.File.Enabled == nil {
		l.File.Enabled = ptr(true)
	}
	if l.File.Path == "" {
		l.File.Path = "logs/snmp-poller.log"
	}
	if l.File.MaxSizeMB == 0 {
		l.File.MaxSizeMB = 50
	}
	if l.File.MaxBackups == nil {
		l.File.MaxBackups = ptr(10)
	}
	if l.File.MaxAgeDays == nil {
		l.File.MaxAgeDays = ptr(30)
	}
	if l.File.Compress == nil {
		l.File.Compress = ptr(true)
	}
	if l.LocalTime == nil {
		l.LocalTime = ptr(false)
	}

	if c.Vault != nil {
		c.Vault.applyDefaults()
	}

	if len(c.Outputs) == 0 {
		c.Outputs = []Output{{Name: "null", Type: "null"}}
	}
}
