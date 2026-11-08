package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultDiscoveryScalars are collected on every discovery run, for every device.
var DefaultDiscoveryScalars = map[string]string{
	"sysDescr":    ".1.3.6.1.2.1.1.1.0",
	"sysObjectID": ".1.3.6.1.2.1.1.2.0",
	"sysName":     ".1.3.6.1.2.1.1.5.0",
}

// SNMP versions after normalization.
const (
	Version1  = "1"
	Version2c = "2c"
	Version3  = "3"
)

// SNMPv3 security levels after normalization.
const (
	NoAuthNoPriv = "noAuthNoPriv"
	AuthNoPriv   = "authNoPriv"
	AuthPriv     = "authPriv"
)

var (
	authProtocols = []string{"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
	privProtocols = []string{"DES", "AES", "AES192", "AES256", "AES192C", "AES256C"}
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	oidPattern    = regexp.MustCompile(`^\.?[0-9]+(\.[0-9]+)*$`)
)

// DeviceSpec is the fully resolved configuration of one enabled device:
// defaults applied, credential and profiles merged, everything validated.
type DeviceSpec struct {
	ID                string
	Address           string
	Port              uint16
	SNMP              SNMP
	PollInterval      time.Duration
	DiscoveryInterval time.Duration
	Timeout           time.Duration
	Retries           int
	MaxOIDsPerRequest int
	MaxRepetitions    uint32
	Outputs           []string
	Trace             bool
	Discovery         Discovery
	Scalars           []Scalar
	Tables            []TableSpec
}

// TableSpec is a validated table with its include patterns compiled.
type TableSpec struct {
	Table
	IncludeRE []*regexp.Regexp
}

// Selects reports whether a row whose match key is key must be polled.
// With no include pattern every row is selected.
func (t *TableSpec) Selects(key string) bool {
	if len(t.IncludeRE) == 0 {
		return true
	}
	for _, re := range t.IncludeRE {
		if re.MatchString(key) {
			return true
		}
	}
	return false
}

// DeviceSpecs returns the resolved specification of every enabled device.
func (c *Config) DeviceSpecs() []DeviceSpec { return c.specs }

func (c *Config) validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	g := c.Global
	if g.Threads < 1 {
		add("global.threads must be >= 1")
	}
	if g.PollInterval < time.Second {
		add("global.poll_interval must be >= 1s")
	}
	if g.DiscoveryInterval < 0 {
		add("global.discovery_interval must be > 0")
	}
	if g.Timeout <= 0 {
		add("global.timeout must be > 0")
	}
	if *g.Retries < 0 {
		add("global.retries must be >= 0")
	}
	if g.MaxOIDsPerRequest < 1 || g.MaxOIDsPerRequest > 128 {
		add("global.max_oids_per_request must be between 1 and 128")
	}
	if g.StatsInterval < time.Second {
		add("global.stats_interval must be >= 1s")
	}

	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		add("logging.level %q: must be debug, info, warn or error", c.Logging.Level)
	}
	if c.Logging.File.MaxSizeMB < 1 {
		add("logging.file.max_size_mb must be >= 1")
	}

	outputs := map[string]bool{}
	for i, o := range c.Outputs {
		switch {
		case o.Name == "":
			add("outputs[%d]: name is required", i)
		case outputs[o.Name]:
			add("outputs[%d]: duplicate name %q", i, o.Name)
		case o.Type == "":
			add("output %q: type is required", o.Name)
		}
		outputs[o.Name] = true
	}

	// Credentials are validated where they are used (see resolve), so an
	// unused credential may reference an unset ${ENV_VAR}.
	c.badProfiles = map[string]bool{}
	for _, name := range sortedKeys(c.Profiles) {
		if err := checkSet(c.Profiles[name], "profile "+name); err != nil {
			c.badProfiles[name] = true
			errs = append(errs, err)
		}
	}

	ids := map[string]bool{}
	for i, d := range c.Devices {
		label := fmt.Sprintf("devices[%d]", i)
		if d.ID != "" {
			label = fmt.Sprintf("device %q", d.ID)
		}
		switch {
		case d.ID == "":
			add("%s: id is required", label)
			continue
		case !idPattern.MatchString(d.ID):
			add("%s: id may only contain letters, digits, '.', '_' and '-'", label)
			continue
		case ids[d.ID]:
			add("%s: duplicate id", label)
			continue
		}
		ids[d.ID] = true
		if d.Enabled != nil && !*d.Enabled {
			continue
		}
		spec, err := c.resolve(d, outputs)
		if err != nil {
			add("%s: %w", label, err)
			continue
		}
		c.specs = append(c.specs, spec)
	}
	return errors.Join(errs...)
}

func (c *Config) resolve(d Device, outputs map[string]bool) (DeviceSpec, error) {
	g := c.Global
	s := DeviceSpec{
		ID:                d.ID,
		Address:           d.Address,
		Port:              firstNonZero(d.Port, g.Port),
		PollInterval:      firstNonZero(d.PollInterval, g.PollInterval),
		DiscoveryInterval: firstNonZero(d.DiscoveryInterval, g.DiscoveryInterval),
		Timeout:           firstNonZero(d.Timeout, g.Timeout),
		Retries:           *g.Retries,
		MaxOIDsPerRequest: firstNonZero(d.MaxOIDsPerRequest, g.MaxOIDsPerRequest),
		MaxRepetitions:    firstNonZero(d.MaxRepetitions, g.MaxRepetitions),
		Trace:             d.Trace,
	}
	if d.Retries != nil {
		s.Retries = *d.Retries
	}
	if d.Address == "" {
		return s, errors.New("address is required")
	}
	if s.PollInterval < time.Second {
		return s, errors.New("poll_interval must be >= 1s")
	}
	if s.Retries < 0 || s.MaxOIDsPerRequest < 1 || s.MaxOIDsPerRequest > 128 {
		return s, errors.New("retries must be >= 0 and max_oids_per_request between 1 and 128")
	}

	// Credentials: named credential first, inline snmp block overrides it.
	if d.Credential != "" {
		cred, ok := c.Credentials[d.Credential]
		if !ok {
			return s, fmt.Errorf("unknown credential %q", d.Credential)
		}
		s.SNMP = cred
	}
	if d.SNMP != nil {
		overlaySNMP(&s.SNMP, *d.SNMP)
	}
	if d.Credential == "" && d.SNMP == nil {
		return s, errors.New("either credential or snmp is required")
	}
	if err := normalizeSNMP(&s.SNMP); err != nil {
		if d.Credential != "" {
			return s, fmt.Errorf("credential %q: %w", d.Credential, err)
		}
		return s, err
	}

	// Outputs: default to every configured output.
	if len(d.Outputs) == 0 {
		for _, o := range c.Outputs {
			s.Outputs = append(s.Outputs, o.Name)
		}
	}
	for _, o := range d.Outputs {
		if !outputs[o] {
			return s, fmt.Errorf("unknown output %q", o)
		}
		s.Outputs = append(s.Outputs, o)
	}

	// Metric sets: profiles in order, then the inline set.
	s.Discovery = Discovery{Scalars: map[string]string{}, Columns: map[string]string{}}
	for k, v := range DefaultDiscoveryScalars {
		s.Discovery.Scalars[k] = v
	}
	sets := make([]Set, 0, len(d.Profiles)+1)
	for _, p := range d.Profiles {
		set, ok := c.Profiles[p]
		if !ok {
			return s, fmt.Errorf("unknown profile %q", p)
		}
		if c.badProfiles[p] {
			return s, fmt.Errorf("profile %q is invalid", p)
		}
		sets = append(sets, set)
	}
	if err := checkSet(d.Set, "inline"); err != nil {
		return s, err
	}
	sets = append(sets, d.Set)

	scalarNames := map[string]bool{}
	tableNames := map[string]bool{}
	for _, set := range sets {
		for k, v := range set.Discovery.Scalars {
			s.Discovery.Scalars[k] = normOID(v)
		}
		for k, v := range set.Discovery.Columns {
			s.Discovery.Columns[k] = normOID(v)
		}
		for _, sc := range set.Scalars {
			if scalarNames[sc.Name] {
				return s, fmt.Errorf("duplicate scalar %q", sc.Name)
			}
			scalarNames[sc.Name] = true
			sc.OID = normOID(sc.OID)
			sc.Modes = normModes(sc.Modes)
			s.Scalars = append(s.Scalars, sc)
		}
		for _, t := range set.Tables {
			if tableNames[t.Name] {
				return s, fmt.Errorf("duplicate table %q", t.Name)
			}
			tableNames[t.Name] = true
			ts := TableSpec{Table: t}
			ts.Columns = make([]Column, len(t.Columns))
			for i, col := range t.Columns {
				col.OID = normOID(col.OID)
				col.Modes = normModes(col.Modes)
				ts.Columns[i] = col
			}
			for _, p := range t.Include {
				ts.IncludeRE = append(ts.IncludeRE, regexp.MustCompile(p)) // already checked
			}
			s.Tables = append(s.Tables, ts)
		}
	}
	for _, t := range s.Tables {
		for _, l := range append([]string{t.Label}, t.Labels...) {
			if l == "" {
				continue
			}
			if _, ok := s.Discovery.Columns[l]; !ok {
				return s, fmt.Errorf("table %q: label %q is not a discovery column", t.Name, l)
			}
		}
	}
	if len(s.Scalars) == 0 && len(s.Tables) == 0 {
		return s, errors.New("nothing to poll: no scalars or tables (check profiles)")
	}
	return s, nil
}

// checkSet validates the syntax of a metric set on its own.
func checkSet(set Set, where string) error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf(where+": "+format, a...))
	}
	for _, k := range sortedKeys(set.Discovery.Scalars) {
		if !oidPattern.MatchString(set.Discovery.Scalars[k]) {
			add("discovery scalar %q: invalid oid %q", k, set.Discovery.Scalars[k])
		}
	}
	for _, k := range sortedKeys(set.Discovery.Columns) {
		if !oidPattern.MatchString(set.Discovery.Columns[k]) {
			add("discovery column %q: invalid oid %q", k, set.Discovery.Columns[k])
		}
	}
	for i, sc := range set.Scalars {
		if sc.Name == "" {
			add("scalars[%d]: name is required", i)
		}
		if !oidPattern.MatchString(sc.OID) {
			add("scalar %q: invalid oid %q", sc.Name, sc.OID)
		}
		if err := checkModes(sc.Modes); err != nil {
			add("scalar %q: %w", sc.Name, err)
		}
	}
	for i, t := range set.Tables {
		if t.Name == "" {
			add("tables[%d]: name is required", i)
		}
		if len(t.Columns) == 0 {
			add("table %q: at least one column is required", t.Name)
		}
		for _, p := range t.Include {
			if _, err := regexp.Compile(p); err != nil {
				add("table %q: include %q: %w", t.Name, p, err)
			}
		}
		cols := map[string]bool{}
		for j, col := range t.Columns {
			switch {
			case col.Name == "":
				add("table %q: columns[%d]: name is required", t.Name, j)
			case cols[col.Name]:
				add("table %q: duplicate column %q", t.Name, col.Name)
			}
			cols[col.Name] = true
			if !oidPattern.MatchString(col.OID) {
				add("table %q: column %q: invalid oid %q", t.Name, col.Name, col.OID)
			}
			if err := checkModes(col.Modes); err != nil {
				add("table %q: column %q: %w", t.Name, col.Name, err)
			}
		}
	}
	return errors.Join(errs...)
}

func checkModes(modes []Mode) error {
	for _, m := range modes {
		switch m {
		case ModeRaw, ModeRate, ModeVolume:
		default:
			return fmt.Errorf("invalid mode %q: must be raw, rate or volume", m)
		}
	}
	return nil
}

func normModes(modes []Mode) []Mode {
	if len(modes) == 0 {
		return []Mode{ModeRaw}
	}
	seen := map[Mode]bool{}
	out := modes[:0:0]
	for _, m := range modes {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func normOID(oid string) string {
	if strings.HasPrefix(oid, ".") {
		return oid
	}
	return "." + oid
}

func overlaySNMP(dst *SNMP, src SNMP) {
	set := func(d *string, s string) {
		if s != "" {
			*d = s
		}
	}
	setSecret := func(d *Secret, s Secret) {
		if s.IsSet() {
			*d = s
		}
	}
	set(&dst.Version, src.Version)
	set(&dst.Transport, src.Transport)
	setSecret(&dst.Community, src.Community)
	set(&dst.Username, src.Username)
	set(&dst.SecurityLevel, src.SecurityLevel)
	set(&dst.AuthProtocol, src.AuthProtocol)
	setSecret(&dst.AuthPassphrase, src.AuthPassphrase)
	set(&dst.PrivProtocol, src.PrivProtocol)
	setSecret(&dst.PrivPassphrase, src.PrivPassphrase)
	set(&dst.ContextName, src.ContextName)
	set(&dst.ContextEngineID, src.ContextEngineID)
}

// normalizeSNMP canonicalizes and validates protocol settings in place.
// Error messages never include secret values.
func normalizeSNMP(s *SNMP) error {
	switch strings.ToLower(strings.TrimPrefix(strings.ToLower(s.Version), "v")) {
	case "1":
		s.Version = Version1
	case "2", "2c":
		s.Version = Version2c
	case "3":
		s.Version = Version3
	case "":
		return errors.New("snmp version is required (1, 2c or 3)")
	default:
		return fmt.Errorf("unsupported snmp version %q (1, 2c or 3)", s.Version)
	}

	switch strings.ToLower(s.Transport) {
	case "", "udp":
		s.Transport = "udp"
	case "tcp":
		s.Transport = "tcp"
	default:
		return fmt.Errorf("unsupported transport %q (udp or tcp)", s.Transport)
	}

	if s.Version != Version3 {
		if !s.Community.IsSet() {
			return fmt.Errorf("snmp v%s requires a community", s.Version)
		}
		return nil
	}

	if s.Username == "" {
		return errors.New("snmp v3 requires a username")
	}
	var err error
	if s.AuthProtocol, err = canon(s.AuthProtocol, authProtocols, map[string]string{"SHA1": "SHA"}); err != nil {
		return fmt.Errorf("auth_protocol: %w", err)
	}
	if s.PrivProtocol, err = canon(s.PrivProtocol, privProtocols, map[string]string{"AES128": "AES"}); err != nil {
		return fmt.Errorf("priv_protocol: %w", err)
	}

	switch strings.ToLower(s.SecurityLevel) {
	case "":
		switch {
		case s.PrivProtocol != "":
			s.SecurityLevel = AuthPriv
		case s.AuthProtocol != "":
			s.SecurityLevel = AuthNoPriv
		default:
			s.SecurityLevel = NoAuthNoPriv
		}
	case "noauthnopriv":
		s.SecurityLevel = NoAuthNoPriv
	case "authnopriv":
		s.SecurityLevel = AuthNoPriv
	case "authpriv":
		s.SecurityLevel = AuthPriv
	default:
		return fmt.Errorf("unsupported security_level %q (noAuthNoPriv, authNoPriv or authPriv)", s.SecurityLevel)
	}

	if s.SecurityLevel != NoAuthNoPriv {
		if s.AuthProtocol == "" {
			return fmt.Errorf("security_level %s requires auth_protocol", s.SecurityLevel)
		}
		if len(s.AuthPassphrase.Reveal()) < 8 {
			return errors.New("auth_passphrase must be at least 8 characters")
		}
	}
	if s.SecurityLevel == AuthPriv {
		if s.PrivProtocol == "" {
			return errors.New("security_level authPriv requires priv_protocol")
		}
		if len(s.PrivPassphrase.Reveal()) < 8 {
			return errors.New("priv_passphrase must be at least 8 characters")
		}
	}

	id := strings.TrimPrefix(strings.ToLower(s.ContextEngineID), "0x")
	if id != "" {
		if _, err := hex.DecodeString(id); err != nil {
			return errors.New("context_engine_id must be a hex string")
		}
	}
	s.ContextEngineID = id
	return nil
}

func canon(v string, allowed []string, aliases map[string]string) (string, error) {
	if v == "" {
		return "", nil
	}
	u := strings.ToUpper(strings.ReplaceAll(v, "-", ""))
	if a, ok := aliases[u]; ok {
		u = a
	}
	for _, p := range allowed {
		if p == u {
			return p, nil
		}
	}
	return "", fmt.Errorf("unsupported value %q (one of %s)", v, strings.Join(allowed, ", "))
}

func firstNonZero[T comparable](vals ...T) T {
	var zero T
	for _, v := range vals {
		if v != zero {
			return v
		}
	}
	return zero
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
