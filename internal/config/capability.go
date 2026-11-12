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
	"slices"
	"sort"
	"strings"

	"github.com/airtg-io/schema"
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
	Detect []string `yaml:"detect"`
	// ReplacedBy names capabilities that take precedence: when one of them
	// applies to the device, this one does not (a fallback for agents
	// without the preferred MIB).
	ReplacedBy []string  `yaml:"replaced_by"`
	Discovery  Discovery `yaml:"discovery"`
	Scalars    []Scalar  `yaml:"scalars"`
	Tables     []Table   `yaml:"tables"`
}

// Discovery lists slow-changing data collected on discovery runs.
// Scalars maps a name to a scalar OID (e.g. sysDescr -> 1.3.6.1.2.1.1.1.0).
// Columns maps a name to a table column that is walked (e.g. ifDescr).
type Discovery struct {
	Scalars map[string]string          `yaml:"scalars"`
	Columns map[string]DiscoveryColumn `yaml:"columns"`
}

// DiscoveryColumn is a table column walked on discovery. Written as a bare
// OID, its rows and values are the column's own. Two forms read other data:
//   - Index: OID belongs to another table: row r takes the value of OID at
//     the index found in column Index at row r (e.g. CISCO-PROCESS-MIB
//     cpmCPUTotalPhysicalIndex pointing into ENTITY-MIB entPhysicalTable,
//     for entPhysicalName);
//   - IndexPart n: the rows of OID, each valued with the n-th
//     sub-identifier (from 1) of its own index (e.g. the entPhysicalIndex
//     that starts the index of CISCO-ENHANCED-MEMPOOL-MIB cempMemPoolTable).
type DiscoveryColumn struct {
	OID       string `yaml:"oid"`
	Index     string `yaml:"index"`
	IndexPart int    `yaml:"index_part"`
}

// String is the OID, followed by the index column or index part if any.
func (c DiscoveryColumn) String() string {
	switch {
	case c.Index != "":
		return c.OID + " at index " + c.Index
	case c.IndexPart > 0:
		return fmt.Sprintf("%s index part %d", c.OID, c.IndexPart)
	}
	return c.OID
}

// UnmarshalYAML accepts a bare OID or a mapping { oid, index }.
func (c *DiscoveryColumn) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&c.OID)
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: a discovery column is an oid or { oid, index } or { oid, index_part }", n.Line)
	}
	// Node.Decode does not inherit the decoder's KnownFields: check here.
	for i := 0; i < len(n.Content); i += 2 {
		if k := n.Content[i].Value; k != "oid" && k != "index" && k != "index_part" {
			return fmt.Errorf("line %d: field %s not found in discovery column", n.Content[i].Line, k)
		}
	}
	type plain DiscoveryColumn
	return n.Decode((*plain)(c))
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
// strictly above Above use hc_oid. Without Speed, every row uses hc_oid.
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
	Detect []string
	// ReplacedBy: capabilities whose presence on a device removes this one.
	ReplacedBy []string
	Discovery  Discovery
	Scalars    []Scalar
	Tables     []TableSpec

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
	if err := errors.Join(checkUnique(caps), checkReplacements(caps)); err != nil {
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
	for i, r := range f.ReplacedBy {
		if !idPattern.MatchString(r) {
			add("replaced_by: invalid capability name %q", r)
		}
		if slices.Contains(f.ReplacedBy[:i], r) {
			add("replaced_by: duplicate %q", r)
		}
	}
	for _, k := range sortedKeys(f.Discovery.Columns) {
		col := f.Discovery.Columns[k]
		if !oidPattern.MatchString(col.OID) {
			add("discovery column %q: invalid oid %q", k, col.OID)
		}
		if col.IndexPart < 0 || (col.IndexPart > 0 && col.Index != "") {
			add("discovery column %q: index_part must be at least 1, without index", k)
		}
		if col.Index == "" {
			continue
		}
		switch ref, ok := f.Discovery.Columns[col.Index]; {
		case !ok:
			add("discovery column %q: index %q is not a discovery column of this capability", k, col.Index)
		case ref.Index != "":
			add("discovery column %q: index %q has an index itself (one level only)", k, col.Index)
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
		if err := checkUnit(sc.Unit, sc.Emitted(), sc.Modes); err != nil {
			add("scalar %q: %w", sc.Name, err)
		}
		if sc.Formula != "" && sc.Unit == UnitNone {
			add("scalar %q: a formula gives a number: its unit cannot be none", sc.Name)
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
			switch {
			case hc.Speed != "" && !isColumn(hc.Speed):
				add("table %q: high_capacity.speed %q is not a discovery column of this capability", t.Name, hc.Speed)
			case hc.Speed == "" && hc.Above != 0:
				add("table %q: high_capacity.above requires high_capacity.speed", t.Name)
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
			if err := checkUnit(col.Unit, col.Emitted(), col.Modes); err != nil {
				add("table %q: column %q: %w", t.Name, col.Name, err)
			}
			if col.Formula != "" && col.Unit == UnitNone {
				add("table %q: column %q: a formula gives a number: its unit cannot be none", t.Name, col.Name)
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
		Discovery:   Discovery{Scalars: map[string]string{}, Columns: map[string]DiscoveryColumn{}},
	}
	for _, oid := range f.Detect {
		c.Detect = append(c.Detect, normOID(oid))
	}
	c.ReplacedBy = f.ReplacedBy
	for k, v := range f.Discovery.Scalars {
		c.Discovery.Scalars[k] = normOID(v)
	}
	for k, v := range f.Discovery.Columns {
		v.OID = normOID(v.OID)
		c.Discovery.Columns[k] = v
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
			if n.Above == 0 && n.Speed != "" {
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
// capabilities apply. A discovery entry may be shared if its OID (and index
// column) is the same.
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
			shareDisc("column", k, c.Discovery.Columns[k].String(), c.Name)
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

// checkReplacements checks that replaced_by names existing capabilities,
// without cycles (a capability replaced, even indirectly, by itself).
func checkReplacements(caps []*Capability) error {
	byName := map[string]*Capability{}
	for _, c := range caps {
		byName[c.Name] = c
	}
	var errs []error
	for _, c := range caps {
		for _, r := range c.ReplacedBy {
			if byName[r] == nil {
				errs = append(errs, fmt.Errorf("capability %q: replaced_by: no capability %q", c.Name, r))
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	// Depth-first search: a capability met again on the current path is a cycle.
	state := map[string]int{} // 1 = on the path, 2 = done
	var visit func(c *Capability, path []string) error
	visit = func(c *Capability, path []string) error {
		switch state[c.Name] {
		case 1:
			return fmt.Errorf("capabilities replace each other: %s", strings.Join(append(path, c.Name), " replaced by "))
		case 2:
			return nil
		}
		state[c.Name] = 1
		for _, r := range c.ReplacedBy {
			if err := visit(byName[r], append(path, c.Name)); err != nil {
				return err
			}
		}
		state[c.Name] = 2
		return nil
	}
	for _, c := range caps {
		if err := visit(c, nil); err != nil {
			return err
		}
	}
	return nil
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

// UnitNone is the unit of an emitted value that has none: a string. It is
// sent as an empty unit.
const UnitNone = "none"

// checkUnit checks a metric's unit: required on every emitted value, from
// the AIrtg unit vocabulary (schema.Units), as the source reports it.
func checkUnit(unit string, emitted bool, modes []Mode) error {
	switch {
	case unit == "" && emitted:
		return errors.New(`unit is required: the unit the device reports the value in, from the AIrtg ` +
			`vocabulary (e.g. octet, packet, percent, second, kilobyte; "none" for a string)`)
	case unit == "" || unit == UnitNone:
		return nil
	case !schema.ValidUnit(unit):
		return fmt.Errorf("unit %q is not in the AIrtg unit vocabulary: lowercase singular words such as "+
			"octet, packet, byte, kilobyte, percent, second, enum, with /s for a rate (see README, Units)", unit)
	case strings.HasSuffix(unit, "/s") && slices.Contains(modes, ModeRate):
		return fmt.Errorf("unit %q is already per second: mode rate would append another /s", unit)
	}
	return nil
}
