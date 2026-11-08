// Package config defines the YAML configuration schema of the poller, its
// defaults, validation, and the resolution of profiles and credentials into
// a flat per-device specification.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the configuration file used when none is given.
const DefaultPath = "etc/snmp-poller.yaml"

// Config is the root of the YAML document.
type Config struct {
	Global      Global          `yaml:"global"`
	Logging     Logging         `yaml:"logging"`
	Outputs     []Output        `yaml:"outputs"`
	Credentials map[string]SNMP `yaml:"credentials"`
	Profiles    map[string]Set  `yaml:"profiles"`
	Devices     []Device        `yaml:"devices"`

	specs       []DeviceSpec
	badProfiles map[string]bool
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
	DataDir           string        `yaml:"data_dir"`
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

// SNMP holds protocol settings and credentials. It is used both for named
// entries under `credentials:` and for a device's inline `snmp:` block.
type SNMP struct {
	Version         string `yaml:"version"`
	Transport       string `yaml:"transport"`
	Community       Secret `yaml:"community"`
	Username        string `yaml:"username"`
	SecurityLevel   string `yaml:"security_level"`
	AuthProtocol    string `yaml:"auth_protocol"`
	AuthPassphrase  Secret `yaml:"auth_passphrase"`
	PrivProtocol    string `yaml:"priv_protocol"`
	PrivPassphrase  Secret `yaml:"priv_passphrase"`
	ContextName     string `yaml:"context_name"`
	ContextEngineID string `yaml:"context_engine_id"`
}

// Set is a reusable group of discovery items and metrics. Profiles are Sets,
// and a device can also declare a Set inline.
type Set struct {
	Discovery Discovery `yaml:"discovery"`
	Scalars   []Scalar  `yaml:"scalars"`
	Tables    []Table   `yaml:"tables"`
}

// Discovery lists slow-changing data collected on discovery runs.
// Scalars maps a name to a scalar OID (e.g. sysDescr -> 1.3.6.1.2.1.1.1.0).
// Columns maps a name to a table column OID that is walked (e.g. ifName).
type Discovery struct {
	Scalars map[string]string `yaml:"scalars"`
	Columns map[string]string `yaml:"columns"`
}

// Mode selects how a value is emitted.
type Mode string

// Supported modes.
const (
	ModeRaw    Mode = "raw"
	ModeRate   Mode = "rate"
	ModeVolume Mode = "volume"
)

// Scalar is a single OID polled every cycle.
type Scalar struct {
	Name  string `yaml:"name"`
	OID   string `yaml:"oid"`
	Modes []Mode `yaml:"modes"`
}

// Table is a set of columns polled for every selected row.
type Table struct {
	Name    string   `yaml:"name"`
	Label   string   `yaml:"label"`
	Include []string `yaml:"include"`
	Labels  []string `yaml:"labels"`
	Columns []Column `yaml:"columns"`
}

// Column is one table column polled for each selected row.
type Column struct {
	Name  string `yaml:"name"`
	OID   string `yaml:"oid"`
	Modes []Mode `yaml:"modes"`
}

// Device is one SNMP agent to poll.
type Device struct {
	ID                string        `yaml:"id"`
	Address           string        `yaml:"address"`
	Port              uint16        `yaml:"port"`
	Enabled           *bool         `yaml:"enabled"`
	Credential        string        `yaml:"credential"`
	SNMP              *SNMP         `yaml:"snmp"`
	Profiles          []string      `yaml:"profiles"`
	PollInterval      time.Duration `yaml:"poll_interval"`
	DiscoveryInterval time.Duration `yaml:"discovery_interval"`
	Timeout           time.Duration `yaml:"timeout"`
	Retries           *int          `yaml:"retries"`
	MaxOIDsPerRequest int           `yaml:"max_oids_per_request"`
	MaxRepetitions    uint32        `yaml:"max_repetitions"`
	Outputs           []string      `yaml:"outputs"`
	Trace             bool          `yaml:"trace"`
	Set               `yaml:",inline"`
}

// Load reads, defaults and validates the configuration file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes, defaults and validates a configuration document.
func Parse(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	cfg.applyDefaults()
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
	if g.DataDir == "" {
		g.DataDir = "data"
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

	if len(c.Outputs) == 0 {
		c.Outputs = []Output{{Name: "null", Type: "null"}}
	}
}
