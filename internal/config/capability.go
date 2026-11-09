package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultHighCapacitySpeed is the default high_capacity.above threshold:
// rows faster than 100 Mbit/s use their 64-bit counters. A 32-bit octet
// counter wraps every 34 s at 1 Gbit/s but every 344 s at 100 Mbit/s.
const DefaultHighCapacitySpeed = 100_000_000

// CapabilityFile is the YAML schema of one file in the capabilities
// directory (capabilities.d). The capability is named after the file.
type CapabilityFile struct {
	Description string `yaml:"description"`
	// Detect lists OID subtrees that must all exist on the agent for the
	// capability to apply. Without it, the capability applies to every
	// device.
	Detect    []string  `yaml:"detect"`
	Discovery Discovery `yaml:"discovery"`
	Scalars   []Scalar  `yaml:"scalars"`
	Tables    []Table   `yaml:"tables"`
}

// Discovery lists slow-changing data collected on discovery runs.
// Scalars maps a name to a scalar OID (e.g. sysDescr -> 1.3.6.1.2.1.1.1.0).
// Columns maps a name to a table column OID that is walked (e.g. ifDescr).
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

// Scalar is a single value polled every cycle. Exactly one of OID, OIDs
// and Formula is set:
//   - OID is polled as is;
//   - OIDs are candidates in order of preference: discovery picks the first
//     one the agent has, and only that one is polled until the next
//     discovery;
//   - Formula computes the value from scalars of the same capability
//     defined above it.
type Scalar struct {
	Name    string   `yaml:"name"`
	OID     string   `yaml:"oid"`
	OIDs    []string `yaml:"oids"`
	Formula string   `yaml:"formula"`
	Unit    string   `yaml:"unit"`
	Modes   []Mode   `yaml:"modes"`
	// Emit false makes the scalar an input of formulas only: it is polled
	// but not sent to sinks.
	Emit *bool `yaml:"emit"`

	Expr *Formula `yaml:"-"` // compiled Formula
}

// Emitted reports whether the scalar's samples are sent to sinks.
func (s *Scalar) Emitted() bool { return s.Emit == nil || *s.Emit }

// Table is a set of columns polled for every selected row.
type Table struct {
	Name         string        `yaml:"name"`
	Label        string        `yaml:"label"`
	Include      []string      `yaml:"include"`
	Labels       []string      `yaml:"labels"`
	HighCapacity *HighCapacity `yaml:"high_capacity"`
	Columns      []Column      `yaml:"columns"`
}

// HighCapacity selects, per row, between a column's oid and its hc_oid
// (typically ifTable 32-bit counters and ifXTable 64-bit counters).
// At discovery, Probe is fetched for the first row: if the agent has it,
// the high-capacity columns are available, and rows whose Speed column is
// strictly above Above use hc_oid.
type HighCapacity struct {
	Probe string `yaml:"probe"`
	Speed string `yaml:"speed"`
	Above uint64 `yaml:"above"`
}

// Column is one table column polled for each selected row. A column with
// only an hc_oid is polled on high-capacity rows only. A column with a
// Formula is not polled: it is computed, per row, from the columns of the
// same table defined above it.
type Column struct {
	Name    string `yaml:"name"`
	OID     string `yaml:"oid"`
	HCOID   string `yaml:"hc_oid"`
	Formula string `yaml:"formula"`
	Unit    string `yaml:"unit"`
	Modes   []Mode `yaml:"modes"`
	// Emit false makes the column an input of formulas only: it is polled
	// but not sent to sinks.
	Emit *bool `yaml:"emit"`

	Expr *Formula `yaml:"-"` // compiled Formula
}

// Emitted reports whether the column's samples are sent to sinks.
func (c *Column) Emitted() bool { return c.Emit == nil || *c.Emit }

// Capability is a validated, normalized capability file.
type Capability struct {
	Name        string
	Description string
	// Detect is empty for capabilities that apply to every device.
	Detect    []string
	Discovery Discovery
	Scalars   []Scalar
	Tables    []TableSpec

	hash string // of the file content, see Fingerprint
}

// TableSpec is a validated table with its include patterns compiled.
type TableSpec struct {
	Table
	IncludeRE []*regexp.Regexp
	// HasFormulas reports whether a column has a formula.
	HasFormulas bool
}

// HasScalarFormulas reports whether a scalar of the capability has a formula.
func (c *Capability) HasScalarFormulas() bool {
	for i := range c.Scalars {
		if c.Scalars[i].Expr != nil {
			return true
		}
	}
	return false
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

// LoadCapabilities reads every *.yaml and *.yml file of dir, one capability
// per file, named after the file. Other files are ignored. Names, metrics
// and discovery entries must be unique across all capabilities, since any
// combination of them can apply to one device.
func LoadCapabilities(dir string) ([]*Capability, error) {
	caps, _, err := loadCapabilities(dir)
	return caps, err
}

// loadCapabilities is LoadCapabilities, also returning the files read.
func loadCapabilities(dir string) ([]*Capability, []fileData, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("capabilities: %w", err)
	}
	var caps []*Capability
	var read []fileData
	var errs []error
	files := map[string]string{}
	for _, e := range entries {
		if !isYAMLFile(e) {
			continue
		}
		ext := filepath.Ext(e.Name())
		name := strings.TrimSuffix(e.Name(), ext)
		if prev, ok := files[name]; ok {
			errs = append(errs, fmt.Errorf("capability %q: defined by both %s and %s", name, prev, e.Name()))
			continue
		}
		files[name] = e.Name()
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		read = append(read, fileData{path, data})
		c, err := ParseCapability(name, bytes.NewReader(data))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		caps = append(caps, c)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, nil, err
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].Name < caps[j].Name })
	if err := checkUnique(caps); err != nil {
		return nil, nil, fmt.Errorf("capabilities in %s: %w", dir, err)
	}
	return caps, read, nil
}

// ParseCapability decodes and validates one capability file.
func ParseCapability(name string, r io.Reader) (*Capability, error) {
	if !idPattern.MatchString(name) {
		return nil, fmt.Errorf("capability name %q (from the file name) may only contain letters, digits, '.', '_' and '-'", name)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var f CapabilityFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := checkCapability(f); err != nil {
		return nil, err
	}
	c := normalizeCapability(name, f)
	sum := sha256.Sum256(data)
	c.hash = hex.EncodeToString(sum[:])
	return c, nil
}

// Fingerprint identifies the capability as a device polls it: its file
// content and the include patterns of its tables (which a device may
// override). Two capabilities with the same fingerprint discover the same.
func (c *Capability) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s", c.Name, c.hash)
	for _, t := range c.Tables {
		fmt.Fprintf(h, "\x00%s%q", t.Name, t.Include)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func checkCapability(f CapabilityFile) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if len(f.Discovery.Scalars) == 0 && len(f.Discovery.Columns) == 0 && len(f.Scalars) == 0 && len(f.Tables) == 0 {
		add("empty capability: no discovery, scalars or tables")
	}
	for _, oid := range f.Detect {
		if !oidPattern.MatchString(oid) {
			add("detect: invalid oid %q", oid)
		}
	}
	for _, k := range sortedKeys(f.Discovery.Scalars) {
		if !oidPattern.MatchString(f.Discovery.Scalars[k]) {
			add("discovery scalar %q: invalid oid %q", k, f.Discovery.Scalars[k])
		}
	}
	for _, k := range sortedKeys(f.Discovery.Columns) {
		if !oidPattern.MatchString(f.Discovery.Columns[k]) {
			add("discovery column %q: invalid oid %q", k, f.Discovery.Columns[k])
		}
	}
	scalars := map[string]bool{}
	for i, sc := range f.Scalars {
		switch {
		case sc.Name == "":
			add("scalars[%d]: name is required", i)
		case scalars[sc.Name]:
			add("duplicate scalar %q", sc.Name)
		}
		switch n := countSet(sc.OID != "", len(sc.OIDs) > 0, sc.Formula != ""); {
		case n != 1:
			add("scalar %q: exactly one of oid, oids and formula is required", sc.Name)
		case sc.OID != "" && !oidPattern.MatchString(sc.OID):
			add("scalar %q: invalid oid %q", sc.Name, sc.OID)
		case sc.Formula != "":
			if len(sc.Modes) > 0 {
				add("scalar %q: modes cannot be used with formula (a formula is always raw)", sc.Name)
			}
			checkFormula(sc.Formula, scalars, func(err error) { add("scalar %q: %w", sc.Name, err) },
				"is not a scalar defined above it in this capability")
		}
		for _, oid := range sc.OIDs {
			if !oidPattern.MatchString(oid) {
				add("scalar %q: oids: invalid oid %q", sc.Name, oid)
			}
		}
		scalars[sc.Name] = true
		if err := checkModes(sc.Modes); err != nil {
			add("scalar %q: %w", sc.Name, err)
		}
	}
	tables := map[string]bool{}
	isColumn := func(name string) bool { _, ok := f.Discovery.Columns[name]; return ok }
	for i, t := range f.Tables {
		switch {
		case t.Name == "":
			add("tables[%d]: name is required", i)
		case tables[t.Name]:
			add("duplicate table %q", t.Name)
		}
		tables[t.Name] = true
		if len(t.Columns) == 0 {
			add("table %q: at least one column is required", t.Name)
		}
		for _, p := range t.Include {
			if _, err := regexp.Compile(p); err != nil {
				add("table %q: include %q: %w", t.Name, p, err)
			}
		}
		for _, l := range append([]string{t.Label}, t.Labels...) {
			if l != "" && !isColumn(l) {
				add("table %q: label %q is not a discovery column of this capability", t.Name, l)
			}
		}
		if hc := t.HighCapacity; hc != nil {
			if t.Label == "" {
				add("table %q: high_capacity requires a label", t.Name)
			}
			if !oidPattern.MatchString(hc.Probe) {
				add("table %q: high_capacity.probe: invalid oid %q", t.Name, hc.Probe)
			}
			if !isColumn(hc.Speed) {
				add("table %q: high_capacity.speed %q is not a discovery column of this capability", t.Name, hc.Speed)
			}
		}
		cols := map[string]bool{}
		polled, computed := false, false
		for j, col := range t.Columns {
			switch {
			case col.Name == "":
				add("table %q: columns[%d]: name is required", t.Name, j)
			case cols[col.Name]:
				add("table %q: duplicate column %q", t.Name, col.Name)
			}
			polled, computed = polled || col.OID != "", computed || col.Formula != ""
			switch {
			case col.Formula != "" && (col.OID != "" || col.HCOID != ""):
				add("table %q: column %q: formula cannot be used with oid or hc_oid", t.Name, col.Name)
			case col.Formula != "":
				if len(col.Modes) > 0 {
					add("table %q: column %q: modes cannot be used with formula (a formula is always raw)", t.Name, col.Name)
				}
				checkFormula(col.Formula, cols, func(err error) { add("table %q: column %q: %w", t.Name, col.Name, err) },
					"is not a column defined above it in this table")
			case col.OID == "" && col.HCOID == "":
				add("table %q: column %q: oid, hc_oid or formula is required", t.Name, col.Name)
			case col.OID != "" && !oidPattern.MatchString(col.OID):
				add("table %q: column %q: invalid oid %q", t.Name, col.Name, col.OID)
			case col.HCOID != "" && !oidPattern.MatchString(col.HCOID):
				add("table %q: column %q: invalid hc_oid %q", t.Name, col.Name, col.HCOID)
			case col.HCOID != "" && t.HighCapacity == nil:
				add("table %q: column %q: hc_oid requires high_capacity on the table", t.Name, col.Name)
			}
			cols[col.Name] = true
			if err := checkModes(col.Modes); err != nil {
				add("table %q: column %q: %w", t.Name, col.Name, err)
			}
		}
		if t.Label == "" && computed && !polled {
			add("table %q: a table without label is walked: at least one column needs an oid", t.Name)
		}
	}
	return errors.Join(errs...)
}

func countSet(set ...bool) int {
	n := 0
	for _, b := range set {
		if b {
			n++
		}
	}
	return n
}

// checkFormula compiles src and checks that it only reads known names (the
// values defined above the formula).
func checkFormula(src string, known map[string]bool, add func(error), unknown string) {
	f, err := ParseFormula(src)
	if err != nil {
		add(err)
		return
	}
	for _, r := range f.Refs() {
		if !known[r] {
			add(fmt.Errorf("formula %q: %q %s", src, r, unknown))
		}
	}
}

func normalizeCapability(name string, f CapabilityFile) *Capability {
	c := &Capability{
		Name:        name,
		Description: f.Description,
		Discovery:   Discovery{Scalars: map[string]string{}, Columns: map[string]string{}},
	}
	for _, oid := range f.Detect {
		c.Detect = append(c.Detect, normOID(oid))
	}
	for k, v := range f.Discovery.Scalars {
		c.Discovery.Scalars[k] = normOID(v)
	}
	for k, v := range f.Discovery.Columns {
		c.Discovery.Columns[k] = normOID(v)
	}
	for _, sc := range f.Scalars {
		if sc.OID != "" {
			sc.OID = normOID(sc.OID)
		}
		oids := make([]string, len(sc.OIDs))
		for i, oid := range sc.OIDs {
			oids[i] = normOID(oid)
		}
		sc.OIDs = oids
		sc.Expr = mustFormula(sc.Formula)
		sc.Modes = normModes(sc.Modes)
		c.Scalars = append(c.Scalars, sc)
	}
	for _, t := range f.Tables {
		ts := TableSpec{Table: t}
		if hc := t.HighCapacity; hc != nil {
			n := *hc
			n.Probe = normOID(n.Probe)
			if n.Above == 0 {
				n.Above = DefaultHighCapacitySpeed
			}
			ts.HighCapacity = &n
		}
		ts.Columns = make([]Column, len(t.Columns))
		for i, col := range t.Columns {
			if col.OID != "" {
				col.OID = normOID(col.OID)
			}
			if col.HCOID != "" {
				col.HCOID = normOID(col.HCOID)
			}
			col.Expr = mustFormula(col.Formula)
			ts.HasFormulas = ts.HasFormulas || col.Expr != nil
			col.Modes = normModes(col.Modes)
			ts.Columns[i] = col
		}
		ts.IncludeRE = compile(t.Include)
		c.Tables = append(c.Tables, ts)
	}
	return c
}

// checkUnique rejects names that would collide on a device to which several
// capabilities apply. A discovery entry may be shared if its OID is the same.
func checkUnique(caps []*Capability) error {
	var errs []error
	owner := map[string]string{}
	claim := func(kind, name, capName string) {
		key := kind + "\x00" + name
		if prev, ok := owner[key]; ok {
			errs = append(errs, fmt.Errorf("%s %q is defined by both %q and %q", kind, name, prev, capName))
			return
		}
		owner[key] = capName
	}
	discOIDs := map[string]string{}
	discOwner := map[string]string{}
	shareDisc := func(kind, name, oid, capName string) {
		key := kind + "\x00" + name
		if prev, ok := discOIDs[key]; ok && prev != oid {
			errs = append(errs, fmt.Errorf("discovery %s %q has different oids in %q (%s) and %q (%s)",
				kind, name, discOwner[key], prev, capName, oid))
			return
		}
		discOIDs[key], discOwner[key] = oid, capName
	}
	for _, c := range caps {
		for _, k := range sortedKeys(c.Discovery.Scalars) {
			shareDisc("scalar", k, c.Discovery.Scalars[k], c.Name)
		}
		for _, k := range sortedKeys(c.Discovery.Columns) {
			shareDisc("column", k, c.Discovery.Columns[k], c.Name)
		}
		for _, s := range c.Scalars {
			claim("scalar", s.Name, c.Name)
		}
		for _, t := range c.Tables {
			claim("table", t.Name, c.Name)
		}
	}
	return errors.Join(errs...)
}

// mustFormula compiles an already checked formula; nil for none.
func mustFormula(src string) *Formula {
	if src == "" {
		return nil
	}
	f, err := ParseFormula(src)
	if err != nil {
		panic(err) // checked by checkCapability
	}
	return f
}

func compile(patterns []string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		res = append(res, regexp.MustCompile(p)) // already checked
	}
	return res
}
