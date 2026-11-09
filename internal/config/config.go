// Package config defines the YAML configuration schema of the poller, its
// defaults, validation, credential encryption, and the resolution of each
// device into a flat specification.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

	// files are the configuration files read: the main file first, then
	// those of the include directory in name order. Seal rewrites them.
	files       []*configFile
	capFiles    []fileData // capability files read
	loggingFile string     // files defining logging and vault, for error messages
	vaultFile   string
}

// configFile is one file of the configuration, decoded on its own: its
// secrets keep their position in that file, for Seal.
type configFile struct {
	path   string // "" for a main document not read from a file
	source []byte
	doc    *Config
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
	// IncludeDir holds more configuration files (*.yaml, *.yml), read in
	// name order after the main file. Only the main file may set it.
	IncludeDir string `yaml:"include_dir"`
	// CapabilitiesDir holds the capabilities, one file each.
	CapabilitiesDir string        `yaml:"capabilities_dir"`
	StatsInterval   time.Duration `yaml:"stats_interval"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	// HotReload reloads the configuration when one of its files changes.
	// SIGHUP reloads it in any case.
	HotReload *bool `yaml:"hot_reload"`
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

	file  string
	index int
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

	file  string // file defining the device ("" = main document)
	index int    // position in that file's devices
}

// Load reads, defaults and validates the configuration file at path, the
// files of its include directory and its capabilities directory. Relative
// global.include_dir and global.capabilities_dir are resolved against the
// directory of path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadFiles(data, path, filepath.Dir(path))
}

// Parse decodes, defaults and validates a main configuration document, the
// files of its include directory and its capabilities. Relative
// global.include_dir and global.capabilities_dir are resolved against
// baseDir.
func Parse(r io.Reader, baseDir string) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return loadFiles(data, "", baseDir)
}

// inFile prefixes err with the file it comes from, when there is one.
func inFile(path string, err error) error {
	if path == "" {
		return err
	}
	return fmt.Errorf("%s: %w", path, err)
}

func loadFiles(data []byte, path, baseDir string) (*Config, error) {
	main, err := decodeFile(data, path, true)
	if err != nil {
		return nil, err
	}
	files := []*configFile{main}
	g := main.doc.Global
	explicit := g.IncludeDir != ""
	if !explicit {
		g.IncludeDir = "conf.d"
	}
	if g.CapabilitiesDir == "" {
		g.CapabilitiesDir = "capabilities.d"
	}
	if !filepath.IsAbs(g.IncludeDir) {
		g.IncludeDir = filepath.Join(baseDir, g.IncludeDir)
	}
	if !filepath.IsAbs(g.CapabilitiesDir) {
		g.CapabilitiesDir = filepath.Join(baseDir, g.CapabilitiesDir)
	}
	if filepath.Clean(g.IncludeDir) == filepath.Clean(g.CapabilitiesDir) {
		return nil, inFile(path, errors.New("global.include_dir and global.capabilities_dir must be different directories"))
	}
	included, err := readIncludeDir(g.IncludeDir, explicit, path)
	if err != nil {
		return nil, err
	}
	files = append(files, included...)

	cfg, err := merge(files)
	if err != nil {
		return nil, err
	}
	cfg.Global.IncludeDir = g.IncludeDir
	cfg.Global.CapabilitiesDir = g.CapabilitiesDir
	cfg.applyDefaults()
	if err := cfg.resolveSecrets(); err != nil {
		return nil, err
	}
	cfg.capabilities, cfg.capFiles, err = loadCapabilities(cfg.Global.CapabilitiesDir)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decodeFile decodes one configuration file strictly (unknown keys are
// errors). Only the main file may hold global.
func decodeFile(data []byte, path string, main bool) (*configFile, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, inFile(path, err)
	}
	top := map[string]*yaml.Node{} // top-level key -> its key node
	if len(root.Content) == 1 && root.Content[0].Kind == yaml.MappingNode {
		m := root.Content[0].Content
		for i := 0; i+1 < len(m); i += 2 {
			top[m[i].Value] = m[i]
			if m[i].Value == "global" && main {
				g := m[i+1].Content
				for j := 0; j+1 < len(g); j += 2 {
					if g[j].Value == "conf_dir" {
						return nil, inFile(path, fmt.Errorf("line %d: global.conf_dir was renamed global.capabilities_dir "+
							"(conf.d now holds configuration files, capabilities moved to capabilities.d)", g[j].Line))
					}
				}
			}
		}
	}
	if k := top["global"]; k != nil && !main {
		return nil, inFile(path, fmt.Errorf("line %d: global is only allowed in the main configuration file", k.Line))
	}
	if !main && (top["detect"] != nil || top["discovery"] != nil || top["scalars"] != nil || top["tables"] != nil) {
		return nil, inFile(path, errors.New("this is a capability, not a configuration file: "+
			"capabilities belong in global.capabilities_dir (capabilities.d), "+
			"the include directory (conf.d) holds configuration files"))
	}
	doc := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, inFile(path, err)
	}
	for i := range doc.Devices {
		doc.Devices[i].file, doc.Devices[i].index = path, i
	}
	for i := range doc.Outputs {
		doc.Outputs[i].file, doc.Outputs[i].index = path, i
	}
	return &configFile{path: path, source: data, doc: doc}, nil
}

// readIncludeDir decodes every *.yaml and *.yml file of dir, in name order.
// Hidden files and subdirectories are ignored. A missing directory is an
// error only when it was configured explicitly.
func readIncludeDir(dir string, explicit bool, mainPath string) ([]*configFile, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return nil, nil
	}
	if err != nil {
		return nil, inFile(mainPath, fmt.Errorf("global.include_dir: %w", err))
	}
	var files []*configFile
	var errs []error
	for _, e := range entries {
		if !isYAMLFile(e) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f, err := decodeFile(data, path, false)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		files = append(files, f)
	}
	return files, errors.Join(errs...)
}

// isYAMLFile reports whether a directory entry is a *.yaml or *.yml file
// to read: hidden files (editor locks and backups) are skipped.
func isYAMLFile(e fs.DirEntry) bool {
	ext := filepath.Ext(e.Name())
	return !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && (ext == ".yaml" || ext == ".yml")
}

// merge combines the configuration files: outputs and devices are
// concatenated in file order; logging and vault may each be defined by
// one file only.
func merge(files []*configFile) (*Config, error) {
	cfg := &Config{Global: files[0].doc.Global, files: files}
	var loggingSet bool
	var errs []error
	for _, f := range files {
		d := f.doc
		if d.Logging != (Logging{}) {
			if loggingSet {
				errs = append(errs, inFile(f.path, fmt.Errorf("logging is already defined in %s", nameOf(cfg.loggingFile))))
			} else {
				cfg.Logging, cfg.loggingFile, loggingSet = d.Logging, f.path, true
			}
		}
		if d.Vault != nil {
			if cfg.Vault != nil {
				errs = append(errs, inFile(f.path, fmt.Errorf("vault is already defined in %s", nameOf(cfg.vaultFile))))
			} else {
				cfg.Vault, cfg.vaultFile = d.Vault, f.path
			}
		}
		cfg.Outputs = append(cfg.Outputs, d.Outputs...)
		cfg.Devices = append(cfg.Devices, d.Devices...)
	}
	return cfg, errors.Join(errs...)
}

// nameOf names a file in messages.
func nameOf(path string) string {
	if path == "" {
		return "the main configuration"
	}
	return path
}

// Files returns the configuration files read: the main file (when read
// from a file) then those of the include directory.
func (c *Config) Files() []string {
	var out []string
	for _, f := range c.files {
		if f.path != "" {
			out = append(out, f.path)
		}
	}
	return out
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
	if g.StatsInterval == 0 {
		g.StatsInterval = time.Minute
	}
	if g.ShutdownTimeout == 0 {
		g.ShutdownTimeout = 30 * time.Second
	}
	if g.HotReload == nil {
		g.HotReload = ptr(true)
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
