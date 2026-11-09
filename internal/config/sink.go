package config

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Sink types.
const (
	// SinkPrometheus pushes with the Prometheus remote write protocol
	// (1.0: protobuf, snappy), accepted by Prometheus, Grafana Mimir,
	// VictoriaMetrics, Thanos, Cortex, ...
	SinkPrometheus = "prometheus"
	// SinkInfluxDB writes InfluxDB line protocol to the /api/v2/write
	// endpoint of InfluxDB 3 (Core, Enterprise, Cloud), also served by
	// InfluxDB 2.
	SinkInfluxDB = "influxdb"
)

// SinkTypes lists the sink types.
var SinkTypes = []string{SinkInfluxDB, SinkPrometheus}

// SinksDir is the directory of the data directory holding the disk
// buffers of the sinks, one subdirectory per sink id. It survives restarts.
const SinksDir = "sinks"

// DefaultDiskBuffer is the default size limit of a sink's disk buffer.
const DefaultDiskBuffer = 1_000_000_000 // 1GB

// Sink is a destination of polled samples: a time series database.
type Sink struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
	// URL is the remote write endpoint (prometheus) or the server base URL
	// (influxdb).
	URL string `yaml:"url"`
	// Database is the InfluxDB database (bucket).
	Database string `yaml:"database"`
	// Token is sent as "Authorization: Token" (influxdb) or "Bearer"
	// (prometheus).
	Token Secret `yaml:"token"`
	// Username and Password are sent with HTTP basic authentication.
	Username      string            `yaml:"username"`
	Password      Secret            `yaml:"password"`
	Headers       map[string]string `yaml:"headers"`
	Timeout       time.Duration     `yaml:"timeout"`
	CACert        string            `yaml:"ca_cert"`
	ClientCert    string            `yaml:"client_cert"`
	ClientKey     string            `yaml:"client_key"`
	TLSSkipVerify bool              `yaml:"tls_skip_verify"`
	// Prefix starts every metric name (prometheus, default "snmp_") or
	// measurement name (influxdb, default none).
	Prefix *string `yaml:"prefix"`
	// Keys selects the keys sent, Tags the tags attached to them.
	Keys KeyFilter `yaml:"keys"`
	Tags TagList   `yaml:"tags"`
	// BatchSize is the number of samples per request; FlushInterval the
	// longest a sample waits for its batch to fill.
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	// DiskBuffer limits the disk buffer of data not yet accepted by the
	// destination, in <data_dir>/sinks/<id>. 0 (or null) disables it.
	DiskBuffer ByteSize `yaml:"disk_buffer"`

	// Resolved by validation.
	ResolvedTags []Tag            `yaml:"-"`
	IncludeRE    []*regexp.Regexp `yaml:"-"`
	ExcludeRE    []*regexp.Regexp `yaml:"-"`

	file  string
	index int
}

// KeyFilter selects keys by regular expression (unanchored, like table
// include patterns). A key is sent when it matches an Include pattern (or
// Include is empty) and no Exclude pattern.
type KeyFilter struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// Sends reports whether the sink sends key.
func (s *Sink) Sends(key string) bool {
	if len(s.IncludeRE) > 0 && !slices.ContainsFunc(s.IncludeRE, func(r *regexp.Regexp) bool { return r.MatchString(key) }) {
		return false
	}
	return !slices.ContainsFunc(s.ExcludeRE, func(r *regexp.Regexp) bool { return r.MatchString(key) })
}

// SampleKey is the key of a sample: its metric name, followed by _rate or
// _volume for those modes. It is the field key (influxdb) and the metric
// name without its prefix (prometheus).
func SampleKey(metric string, mode Mode) string {
	if mode == ModeRaw || mode == "" {
		return metric
	}
	return metric + "_" + string(mode)
}

// TagRef is one entry of a sink's tags: the tag Name and where its value
// comes from.
type TagRef struct {
	Name, Source string
}

// TagList is a sink's `tags`: a list whose entries are a source name (the
// tag is named after it) or a one-key mapping {tag name: source}.
type TagList []TagRef

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *TagList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: tags must be a list of sources, or of {tag: source}", n.Line)
	}
	out := TagList{}
	for _, e := range n.Content {
		switch {
		case e.Kind == yaml.ScalarNode && e.ShortTag() == "!!str":
			out = append(out, TagRef{e.Value, e.Value})
		case e.Kind == yaml.MappingNode && len(e.Content) == 2 &&
			e.Content[0].ShortTag() == "!!str" && e.Content[1].ShortTag() == "!!str":
			out = append(out, TagRef{e.Content[0].Value, e.Content[1].Value})
		default:
			return fmt.Errorf("line %d: tag must be a source name or {tag: source}", e.Line)
		}
	}
	*t = out
	return nil
}

// Tag sources that are not discovery data.
const (
	TagDevice     = "device"     // device id
	TagAddress    = "address"    // device address
	TagIndex      = "index"      // table row index
	TagTable      = "table"      // table name
	TagCapability = "capability" // capability name
	TagLabels     = "labels"     // the table's label and labels columns, each its own tag
)

// TagKind tells where a tag's value comes from.
type TagKind int

// Tag kinds.
const (
	KindDevice TagKind = iota
	KindAddress
	KindIndex
	KindTable
	KindCapability
	KindLabels
	KindScalar // a discovery scalar (sysName, ...)
	KindColumn // a discovery column, at the row's index
)

// Tag is a resolved tag.
type Tag struct {
	Name   string
	Source string
	Kind   TagKind
	// Capabilities owning the discovery column (KindColumn): the column
	// only tags rows of their tables.
	Capabilities []string
}

// DefaultTags are the tags of a sink that sets none.
var DefaultTags = TagList{{TagDevice, TagDevice}, {TagIndex, TagIndex}, {TagLabels, TagLabels}}

// ByteSize is a size in bytes, written as a number of bytes or with a unit:
// KB, MB, GB, TB (powers of 1000) or KiB, MiB, GiB, TiB (powers of 1024).
type ByteSize struct {
	Bytes int64
	Set   bool // written in the file, possibly as null
}

var sizePattern = regexp.MustCompile(`^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)\s*$`)

var sizeUnits = map[string]float64{
	"": 1, "b": 1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

// ParseByteSize parses a size such as 1GB, 512MiB or 1000000.
func ParseByteSize(s string) (int64, error) {
	m := sizePattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (examples: 1GB, 500MB, 2GiB)", s)
	}
	unit, ok := sizeUnits[strings.ToLower(m[2])]
	if !ok {
		return 0, fmt.Errorf("invalid size %q: unknown unit %q (B, KB, MB, GB, TB, KiB, MiB, GiB, TiB)", s, m[2])
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	if f*unit >= math.MaxInt64 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return int64(f * unit), nil
}

// UnmarshalYAML implements yaml.Unmarshaler. A null value is handled by
// decodeFile: yaml does not call UnmarshalYAML for null.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: a size is expected (examples: 1GB, 500MB, 0)", n.Line)
	}
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = ByteSize{Bytes: v, Set: true}
	return nil
}

func (b ByteSize) String() string {
	switch {
	case b.Bytes == 0:
		return "0"
	case b.Bytes%1e9 == 0:
		return fmt.Sprintf("%dGB", b.Bytes/1e9)
	case b.Bytes%1e6 == 0:
		return fmt.Sprintf("%dMB", b.Bytes/1e6)
	}
	return fmt.Sprintf("%dB", b.Bytes)
}

func (s *Sink) applyDefaults() {
	if s.Timeout == 0 {
		s.Timeout = 10 * time.Second
	}
	if s.BatchSize == 0 {
		s.BatchSize = 5000
	}
	if s.FlushInterval == 0 {
		s.FlushInterval = time.Second
	}
	if !s.DiskBuffer.Set {
		s.DiskBuffer = ByteSize{Bytes: DefaultDiskBuffer, Set: true}
	}
	if s.Prefix == nil {
		p := ""
		if s.Type == SinkPrometheus {
			p = "snmp_"
		}
		s.Prefix = &p
	}
	if s.Tags == nil {
		s.Tags = slices.Clone(DefaultTags)
	}
}

var (
	promLabel  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	promMetric = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
)

// validate checks a sink and resolves its tags and key filters against the
// capabilities.
func (s *Sink) validate(caps []*Capability) error {
	if !slices.Contains(SinkTypes, s.Type) {
		if s.Type == "null" {
			return errors.New(`type "null" was removed: a configuration without sinks sends data nowhere`)
		}
		return fmt.Errorf("type %q: must be %s", s.Type, strings.Join(SinkTypes, " or "))
	}
	u, err := url.Parse(s.URL)
	switch {
	case s.URL == "":
		return errors.New("url is required")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return fmt.Errorf("url %q must be an http:// or https:// URL", s.URL)
	case u.User != nil:
		return errors.New("url: put credentials in username/password or token (encrypted), not in the URL")
	case s.Type == SinkInfluxDB && s.Database == "":
		return errors.New("database is required")
	case s.Type != SinkInfluxDB && s.Database != "":
		return fmt.Errorf("database is only used by influxdb sinks")
	case s.Timeout < 0:
		return errors.New("timeout must be > 0")
	case s.BatchSize < 1:
		return errors.New("batch_size must be >= 1")
	case s.FlushInterval < 0:
		return errors.New("flush_interval must be > 0")
	case s.DiskBuffer.Bytes < 0:
		return errors.New("disk_buffer must be >= 0")
	case s.Token.IsSet() && (s.Username != "" || s.Password.IsSet()):
		return errors.New("token and username/password are exclusive")
	case s.Password.IsSet() && s.Username == "":
		return errors.New("password requires username")
	case (s.ClientCert == "") != (s.ClientKey == ""):
		return errors.New("client_cert and client_key go together")
	}
	for k := range s.Headers {
		if strings.EqualFold(k, "Authorization") {
			return errors.New("headers: set Authorization with token or username/password, they are encrypted")
		}
	}
	if s.Type == SinkPrometheus && *s.Prefix != "" && !promMetric.MatchString(*s.Prefix) {
		return fmt.Errorf("prefix %q: must match %s", *s.Prefix, promMetric)
	}

	if s.IncludeRE, err = compileAll("keys.include", s.Keys.Include); err != nil {
		return err
	}
	if s.ExcludeRE, err = compileAll("keys.exclude", s.Keys.Exclude); err != nil {
		return err
	}

	s.ResolvedTags = nil
	names := map[string]bool{}
	for _, ref := range s.Tags {
		t, err := resolveTag(ref, caps)
		if err != nil {
			return err
		}
		if names[t.Name] {
			return fmt.Errorf("tags: duplicate tag %q", t.Name)
		}
		names[t.Name] = true
		if s.Type == SinkPrometheus && (!promLabel.MatchString(t.Name) || strings.HasPrefix(t.Name, "__")) {
			return fmt.Errorf("tags: %q is not a valid Prometheus label name", t.Name)
		}
		if s.Type == SinkInfluxDB && t.Name == "time" {
			return errors.New(`tags: "time" is reserved by InfluxDB`)
		}
		s.ResolvedTags = append(s.ResolvedTags, t)
	}
	return s.checkKeys(caps)
}

func compileAll(what string, patterns []string) ([]*regexp.Regexp, error) {
	var res []*regexp.Regexp
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, p, err)
		}
		res = append(res, r)
	}
	return res, nil
}

func resolveTag(ref TagRef, caps []*Capability) (Tag, error) {
	t := Tag{Name: ref.Name, Source: ref.Source}
	switch ref.Source {
	case TagDevice:
		t.Kind = KindDevice
	case TagAddress:
		t.Kind = KindAddress
	case TagIndex:
		t.Kind = KindIndex
	case TagTable:
		t.Kind = KindTable
	case TagCapability:
		t.Kind = KindCapability
	case TagLabels:
		if ref.Name != TagLabels {
			return t, errors.New("tags: labels cannot be renamed: each label is a tag named after its column")
		}
		t.Kind = KindLabels
	default:
		for _, c := range caps {
			if _, ok := c.Discovery.Scalars[ref.Source]; ok {
				t.Kind = KindScalar
				return t, nil
			}
			if _, ok := c.Discovery.Columns[ref.Source]; ok {
				t.Kind = KindColumn
				t.Capabilities = append(t.Capabilities, c.Name)
			}
		}
		if t.Kind != KindColumn {
			return t, fmt.Errorf("tags: unknown source %q: must be device, address, index, table, capability, "+
				"labels, or a discovery scalar or column of a capability", ref.Source)
		}
	}
	if ref.Name == "" {
		return t, errors.New("tags: empty tag name")
	}
	return t, nil
}

// checkKeys makes sure what the sink writes is consistent: a Prometheus
// metric name is emitted by one table or capability only; an InfluxDB tag
// is never also a field of the same measurement.
func (s *Sink) checkKeys(caps []*Capability) error {
	owner := map[string]string{} // prometheus metric name -> emitter
	for _, c := range caps {
		var groups []struct {
			measurement string
			table       *TableSpec
			keys        []string
		}
		var scalarKeys []string
		for _, sc := range c.Scalars {
			if sc.Emitted() {
				scalarKeys = append(scalarKeys, modeKeys(sc.Name, sc.Modes)...)
			}
		}
		groups = append(groups, struct {
			measurement string
			table       *TableSpec
			keys        []string
		}{c.Name, nil, scalarKeys})
		for i := range c.Tables {
			t := &c.Tables[i]
			var keys []string
			for _, col := range t.Columns {
				if col.Emitted() {
					keys = append(keys, modeKeys(col.Name, col.Modes)...)
				}
			}
			groups = append(groups, struct {
				measurement string
				table       *TableSpec
				keys        []string
			}{t.Name, t, keys})
		}
		for _, g := range groups {
			emitter := fmt.Sprintf("capability %q", c.Name)
			if g.table != nil {
				emitter = fmt.Sprintf("table %q of capability %q", g.table.Name, c.Name)
			}
			for _, k := range g.keys {
				if !s.Sends(k) {
					continue
				}
				switch s.Type {
				case SinkPrometheus:
					name := PromName(*s.Prefix + k)
					if prev, ok := owner[name]; ok && prev != emitter {
						return fmt.Errorf("metric %s is emitted by %s and %s: exclude one with keys", name, prev, emitter)
					}
					owner[name] = emitter
				case SinkInfluxDB:
					for _, tag := range s.tagNames(c, g.table) {
						if tag == k {
							return fmt.Errorf("tag %q is also a field of measurement %q (%s): rename the tag",
								tag, *s.Prefix+g.measurement, emitter)
						}
					}
				}
			}
		}
	}
	return nil
}

// tagNames returns the names of the tags the sink may attach to samples
// of capability c, of table t (nil for scalars).
func (s *Sink) tagNames(c *Capability, t *TableSpec) []string {
	var names []string
	for _, tag := range s.ResolvedTags {
		switch tag.Kind {
		case KindIndex, KindTable:
			if t != nil {
				names = append(names, tag.Name)
			}
		case KindLabels:
			if t != nil {
				if t.Label != "" {
					names = append(names, t.Label)
				}
				names = append(names, t.Labels...)
			}
		case KindColumn:
			if t != nil && slices.Contains(tag.Capabilities, c.Name) {
				names = append(names, tag.Name)
			}
		default:
			names = append(names, tag.Name)
		}
	}
	return names
}

func modeKeys(name string, modes []Mode) []string {
	if len(modes) == 0 {
		return []string{name}
	}
	keys := make([]string, 0, len(modes))
	for _, m := range modes {
		keys = append(keys, SampleKey(name, m))
	}
	return keys
}

// PromName turns s into a valid Prometheus metric or label name: every
// invalid character becomes '_'.
func PromName(s string) string {
	b := []byte(s)
	for i, c := range b {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == ':' || i > 0 && c >= '0' && c <= '9'
		if !ok {
			b[i] = '_'
		}
	}
	return string(b)
}

// Equal reports whether two sinks have the same configuration: a sink
// whose configuration did not change keeps running on reload.
func (s *Sink) Equal(o *Sink) bool {
	return s.key() == o.key()
}

func (s *Sink) key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q %q %q %q %q %q %q %v %q %q %q %v %q %q %d %v %d|",
		s.ID, s.Type, s.URL, s.Database, s.Token.Reveal(), s.Username, s.Password.Reveal(),
		s.Timeout, s.CACert, s.ClientCert, s.ClientKey, s.TLSSkipVerify, *s.Prefix,
		s.Keys, s.BatchSize, s.FlushInterval, s.DiskBuffer.Bytes)
	for _, k := range sortedKeys(s.Headers) {
		fmt.Fprintf(&b, "%q=%q ", k, s.Headers[k])
	}
	for _, t := range s.ResolvedTags {
		fmt.Fprintf(&b, "|%q %q %d %q", t.Name, t.Source, t.Kind, t.Capabilities)
	}
	return b.String()
}
