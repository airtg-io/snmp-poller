package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SNMP versions after normalization.
const (
	Version1  = "1"
	Version2c = "2c"
	Version3  = "3"
)

// Transports and walk modes after normalization.
const (
	TransportUDP = "udp"
	TransportTCP = "tcp"
	// WalkBulk walks tables with GETBULK (SNMPv2c/v3), WalkGetNext with
	// GETNEXT, one OID per request (the only way on SNMPv1).
	WalkBulk    = "bulk"
	WalkGetNext = "getnext"
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
// defaults applied, everything validated. When VaultPath is set, SNMP is
// only complete once WithVaultSecret has merged the Vault secret.
type DeviceSpec struct {
	ID                string
	Address           string
	Port              uint16
	Transport         string
	Walk              string
	SNMP              SNMP
	VaultPath         string
	PollInterval      time.Duration
	DiscoveryInterval time.Duration
	Timeout           time.Duration
	Retries           int
	MaxOIDsPerRequest int
	MaxRepetitions    uint32
	Sinks             []string
	Trace             bool
	// Capabilities are the candidates for this device (every capability not
	// excluded), with the device's include overrides applied. Discovery
	// decides which of them the device actually has.
	Capabilities []*Capability

	walkSet bool // walk set on the device itself, not inherited
}

// DeviceSpecs returns the resolved specification of every enabled device.
func (c *Config) DeviceSpecs() []DeviceSpec { return c.specs }

// Capabilities returns every capability loaded from the capabilities
// directory, sorted by name.
func (c *Config) Capabilities() []*Capability { return c.capabilities }

func (c *Config) validate() error {
	var errs []error
	// in returns a function adding an error of file.
	in := func(file string) func(format string, a ...any) {
		return func(format string, a ...any) { errs = append(errs, inFile(file, fmt.Errorf(format, a...))) }
	}

	add := in(c.files[0].path)
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
	if _, err := normTransport(g.Transport); err != nil {
		add("global.%w", err)
	}
	if _, err := normWalk(g.Walk); err != nil {
		add("global.%w", err)
	}

	add = in(c.loggingFile)
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		add("logging.level %q: must be debug, info, warn or error", c.Logging.Level)
	}
	if c.Logging.File.MaxSizeMB < 1 {
		add("logging.file.max_size_mb must be >= 1")
	}

	sinks := map[string]string{} // id -> file defining it
	airtg := ""                  // id of the airtg sink
	for i := range c.Sinks {
		k := &c.Sinks[i]
		add = in(k.file)
		switch prev, dup := sinks[k.ID]; {
		case k.ID == "":
			add("sinks[%d]: id is required", k.index)
			continue
		case !idPattern.MatchString(k.ID):
			add("sink %q: id may only contain letters, digits, '.', '_' and '-'", k.ID)
			continue
		case dup:
			add("sinks[%d]: duplicate id %q (also in %s)", k.index, k.ID, nameOf(prev))
			continue
		}
		sinks[k.ID] = k.file
		if k.Type == SinkAirtg {
			if airtg != "" {
				add("sink %q: only one sink of type airtg is allowed (%q is one already)", k.ID, airtg)
				continue
			}
			airtg = k.ID
		}
		if err := k.validate(c.capabilities); err != nil {
			add("sink %q: %w", k.ID, err)
		}
	}

	// Credentials are validated where they are used (see resolve and
	// Vault.validate), so an unused one may reference an unset ${ENV_VAR}.
	usesVault := false
	for _, d := range c.Devices {
		if d.SNMP != nil && d.SNMP.Vault.Enabled && (d.Enabled == nil || *d.Enabled) {
			usesVault = true
		}
	}
	if c.Vault != nil {
		if err := c.Vault.validate(usesVault); err != nil {
			errs = append(errs, inFile(c.vaultFile, err))
		}
	}

	ids := map[string]string{}       // id -> label of the device using it
	endpoints := map[string]string{} // address/port -> id
	for i, d := range c.Devices {
		add = in(d.file)
		label := fmt.Sprintf("devices[%d]", d.index)
		if d.Address == "" {
			add("%s: address is required", label)
			continue
		}
		port := firstNonZero(d.Port, c.Global.Port)
		if d.ID == "" {
			d.ID = DefaultID(d.Address, port)
		}
		label = fmt.Sprintf("device %q", d.ID)
		switch {
		case !idPattern.MatchString(d.ID):
			add("%s: id may only contain letters, digits, '.', '_' and '-'", label)
			continue
		case d.ID == KeyFile || d.ID == SinksDir:
			add("%s: id %q is reserved (a file of the data directory)", label, d.ID)
			continue
		case ids[d.ID] != "":
			add("%s: duplicate id (also %s)", label, ids[d.ID])
			continue
		}
		ids[d.ID] = fmt.Sprintf("devices[%d]", d.index)
		if d.file != "" {
			ids[d.ID] = d.file + " " + ids[d.ID]
		}
		// The same agent may only be polled twice for two SNMPv3 contexts.
		ep := endpoint(d.Address, port)
		if d.SNMP != nil {
			ep += " " + d.SNMP.ContextName
		}
		if other, ok := endpoints[ep]; ok {
			add("%s: address %s port %d is already used by device %q", label, d.Address, port, other)
			continue
		}
		endpoints[ep] = d.ID
		c.Devices[i].ID = d.ID
		if d.Enabled != nil && !*d.Enabled {
			continue
		}
		spec, err := c.resolve(d, sinks)
		if err != nil {
			add("%s: %w", label, err)
			continue
		}
		c.specs = append(c.specs, spec)
	}
	return errors.Join(errs...)
}

// DefaultID is the id of a device that has none: <address>-<port>, every
// character an id may not contain replaced with '_' (IPv6 colons, zones).
func DefaultID(address string, port uint16) string {
	id := []byte(fmt.Sprintf("%s-%d", address, port))
	for i, b := range id {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
			id[i] = '_'
		}
	}
	return string(id)
}

// endpoint identifies an agent: the address (IPs in canonical form, host
// names case-insensitive, not resolved) and the port.
func endpoint(address string, port uint16) string {
	a := strings.ToLower(strings.TrimSuffix(address, "."))
	if ip, err := netip.ParseAddr(a); err == nil {
		a = ip.Unmap().String()
	}
	return net.JoinHostPort(a, strconv.Itoa(int(port)))
}

func (c *Config) resolve(d Device, sinks map[string]string) (DeviceSpec, error) {
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

	var err error
	if s.Transport, err = normTransport(firstNonZero(d.Transport, g.Transport)); err != nil {
		return s, err
	}
	s.walkSet = d.Walk != ""
	if s.Walk, err = normWalk(firstNonZero(d.Walk, g.Walk)); err != nil {
		return s, err
	}

	if d.SNMP == nil {
		return s, errors.New("snmp is required (version and community, or v3 username and passwords)")
	}
	s.SNMP = *d.SNMP
	if v := d.SNMP.Vault; v.Enabled {
		if c.Vault == nil {
			return s, errors.New("snmp.vault requires a vault section")
		}
		// Validated when the secret is read, at every discovery.
		s.VaultPath = v.Path
		if s.VaultPath == "" {
			s.VaultPath = c.Vault.Prefix + "/" + d.ID
		}
	} else if err := s.finishSNMP(); err != nil {
		return s, err
	}

	// Sinks: default to every configured sink.
	if d.Sinks == nil {
		for _, k := range c.Sinks {
			s.Sinks = append(s.Sinks, k.ID)
		}
	}
	for _, id := range d.Sinks {
		if _, ok := sinks[id]; !ok {
			return s, fmt.Errorf("unknown sink %q", id)
		}
		if slices.Contains(s.Sinks, id) {
			return s, fmt.Errorf("sinks: %q is listed twice", id)
		}
		s.Sinks = append(s.Sinks, id)
	}

	caps, err := c.deviceCapabilities(d)
	if err != nil {
		return s, err
	}
	s.Capabilities = caps
	return s, nil
}

// deviceCapabilities returns every capability not excluded by d, with d's
// include overrides applied (on copies: capabilities are shared).
func (c *Config) deviceCapabilities(d Device) ([]*Capability, error) {
	excluded := map[string]bool{}
	for _, name := range d.Exclude {
		if !slices.ContainsFunc(c.capabilities, func(c *Capability) bool { return c.Name == name }) {
			return nil, fmt.Errorf("exclude: unknown capability %q", name)
		}
		excluded[name] = true
	}
	for _, name := range sortedKeys(d.Include) {
		for _, p := range d.Include[name] {
			if _, err := regexp.Compile(p); err != nil {
				return nil, fmt.Errorf("include: table %q: %q: %w", name, p, err)
			}
		}
	}
	tables := map[string]bool{}
	var caps []*Capability
	for _, cp := range c.capabilities {
		if excluded[cp.Name] {
			continue
		}
		override := false
		for _, t := range cp.Tables {
			tables[t.Name] = true
			_, ok := d.Include[t.Name]
			override = override || ok
		}
		if override {
			cp2 := *cp
			cp2.Tables = slices.Clone(cp.Tables)
			for i := range cp2.Tables {
				t := &cp2.Tables[i]
				if p, ok := d.Include[t.Name]; ok {
					t.Include = p
					t.IncludeRE = compile(p)
				}
			}
			cp = &cp2
		}
		caps = append(caps, cp)
	}
	if len(caps) == 0 {
		return nil, errors.New("every capability is excluded: nothing to poll")
	}
	for _, name := range sortedKeys(d.Include) {
		if !tables[name] {
			return nil, fmt.Errorf("include: unknown table %q (or its capability is excluded)", name)
		}
	}
	return caps, nil
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

// finishSNMP normalizes and validates the SNMP settings, and settles the
// walk mode: SNMPv1 has no GETBULK.
func (s *DeviceSpec) finishSNMP() error {
	if err := normalizeSNMP(&s.SNMP); err != nil {
		return err
	}
	if s.SNMP.Version == Version1 && s.Walk == WalkBulk {
		if s.walkSet {
			return errors.New("walk: bulk is not available in SNMPv1 (use getnext)")
		}
		s.Walk = WalkGetNext
	}
	return nil
}

func normTransport(t string) (string, error) {
	switch strings.ToLower(t) {
	case TransportUDP:
		return TransportUDP, nil
	case TransportTCP:
		return TransportTCP, nil
	}
	return "", fmt.Errorf("transport %q: must be udp or tcp", t)
}

func normWalk(w string) (string, error) {
	switch strings.ToLower(w) {
	case WalkBulk:
		return WalkBulk, nil
	case WalkGetNext:
		return WalkGetNext, nil
	}
	return "", fmt.Errorf("walk %q: must be bulk or getnext", w)
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
		if len(s.AuthPassword.Reveal()) < 8 {
			return errors.New("auth_password must be at least 8 characters")
		}
	}
	if s.SecurityLevel == AuthPriv {
		if s.PrivProtocol == "" {
			return errors.New("security_level authPriv requires priv_protocol")
		}
		if !s.PrivPassword.IsSet() {
			s.PrivPassword = s.AuthPassword
		}
		if len(s.PrivPassword.Reveal()) < 8 {
			return errors.New("priv_password must be at least 8 characters")
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
