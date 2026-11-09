package poller

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/snmp"
	"github.com/airtg-io/snmp-poller/internal/state"
)

// Discovery is the result of a discovery run on one device. It is cached on
// disk (data/<device_id>/discovery.json) and read back by every poll until
// the next discovery.
type Discovery struct {
	Time time.Time `json:"time"`
	// Capabilities are the names of the capabilities the device has.
	Capabilities []string          `json:"capabilities"`
	Scalars      map[string]string `json:"scalars"`
	// Columns maps a discovery column name to index -> value.
	Columns map[string]map[string]string `json:"columns"`
	// Tables holds the row selection of every labelled table.
	Tables map[string]*TableDiscovery `json:"tables"`
	// Sources maps a scalar with candidate oids to the one the agent has.
	Sources map[string]string `json:"sources"`
}

// TableDiscovery is the row selection of one labelled table.
type TableDiscovery struct {
	// Rows are the selected row indexes, in OID order.
	Rows []string `json:"rows"`
	// HighCapacity reports whether the agent answered the high_capacity
	// probe. HighCapacityRows are the selected rows polled with hc_oid.
	HighCapacity     bool     `json:"high_capacity"`
	HighCapacityRows []string `json:"high_capacity_rows,omitempty"`
}

// device is the runtime state of one configured device. Fields are only
// touched by the worker currently polling it (the scheduler guarantees at
// most one poll per device at a time). Discovery data lives on disk.
type device struct {
	spec    config.DeviceSpec
	log     *slog.Logger
	outputs []output.Output
	vault   secretReader // set when spec.VaultPath is

	discoveredAt time.Time // zero until the first successful discovery
	failing      bool
	// fromVault is spec completed with the Vault secret, read at every
	// discovery and only kept in memory.
	fromVault *config.DeviceSpec

	// Scheduler only: next poll and poll interval.
	next     time.Time
	interval time.Duration

	// Protected by Poller.mu.
	busy    bool          // queued or being polled
	removed bool          // no longer in the configuration
	latest  *deviceConf   // last configuration applied or pending
	pending *deviceConf   // configuration to apply when the poll ends
	waiters []*retirement // retired outputs waiting for this poll to end
}

// applyConf sets the device's configuration. Only called while the device
// is not being polled.
func (d *device) applyConf(dc *deviceConf) {
	d.spec, d.log, d.outputs, d.vault = dc.spec, dc.log, dc.outputs, dc.vault
	if dc.rediscover {
		d.discoveredAt = time.Time{}
	}
	if dc.resetVault {
		d.fromVault = nil
	}
}

// secretReader reads a KV secret (see package vault).
type secretReader interface {
	Read(ctx context.Context, path string) (map[string]string, error)
}

// pollResult summarizes one poll for statistics.
type pollResult struct {
	discovered   bool
	discoveryErr bool
	samples      int
	missing      int
	outputErrs   int
}

// poll runs one cycle on the device: discovery when due, then the metrics.
func (d *device) poll(ctx context.Context, store *state.Store, now func() time.Time) (res pollResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, d.deadline())
	defer cancel()

	due := d.discoveredAt.IsZero() || now().Sub(d.discoveredAt) >= d.spec.DiscoveryInterval
	spec, err := d.credentials(ctx, due)
	if err != nil {
		return res, err
	}
	c, err := snmp.Dial(ctx, spec)
	if err != nil {
		return res, err
	}
	defer c.Close()

	disc, err := d.discovery(c, store, now, due, &res)
	if err != nil {
		return res, err
	}

	batch, missing, err := d.collect(c, store, disc, now)
	if err != nil {
		return res, err
	}
	res.missing = missing
	res.samples = len(batch.Samples)
	for i, o := range d.outputs {
		if err := o.Write(ctx, batch); err != nil {
			res.outputErrs++
			d.log.Warn("output write failed", "output", d.spec.Outputs[i], "err", err)
		}
	}
	return res, nil
}

// discovery returns the device's discovery: from the on-disk cache, or from
// a new discovery run when one is due or the cache cannot be read.
func (d *device) discovery(c *snmp.Client, store *state.Store, now func() time.Time, due bool, res *pollResult) (*Discovery, error) {
	if !due {
		disc := &Discovery{}
		err := store.LoadDiscovery(d.spec.ID, disc)
		if err == nil {
			return disc, nil
		}
		d.log.Warn("discovery cache unreadable, rediscovering", "err", err)
	}

	res.discovered = true
	start := now()
	disc, err := d.discover(c, now)
	if err != nil {
		res.discoveryErr = true
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// Row indexes may have changed: previous values are meaningless.
	if err := store.ResetDevice(d.spec.ID); err != nil {
		return nil, fmt.Errorf("reset state: %w", err)
	}
	if err := store.SaveDiscovery(d.spec.ID, disc); err != nil {
		return nil, fmt.Errorf("save discovery: %w", err)
	}
	d.discoveredAt = start
	d.log.Debug("discovery done", "duration", roundDur(now().Sub(start)),
		"capabilities", disc.Capabilities, "scalars", len(disc.Scalars),
		"columns", len(disc.Columns), "rows", rowCount(disc))
	return disc, nil
}

// credentials returns the spec to poll with. For a device whose credentials
// live in Vault, the secret is read again when a discovery is due; if Vault
// fails then, the previous credentials are kept.
func (d *device) credentials(ctx context.Context, due bool) (*config.DeviceSpec, error) {
	if d.spec.VaultPath == "" {
		return &d.spec, nil
	}
	if d.fromVault != nil && !due {
		return d.fromVault, nil
	}
	spec, err := d.readVault(ctx)
	if err != nil {
		if d.fromVault == nil {
			return nil, err
		}
		d.log.Warn("credentials refresh failed, keeping the previous ones", "err", err)
		return d.fromVault, nil
	}
	d.log.Debug("credentials read from vault", "path", d.spec.VaultPath)
	d.fromVault = spec
	return spec, nil
}

func (d *device) readVault(ctx context.Context) (*config.DeviceSpec, error) {
	secret, err := d.vault.Read(ctx, d.spec.VaultPath)
	if err != nil {
		return nil, err
	}
	spec, err := d.spec.WithVaultSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("vault secret %s: %w", d.spec.VaultPath, err)
	}
	return spec, nil
}

// deadline bounds a whole poll so a stuck device cannot hold a worker forever.
func (d *device) deadline() time.Duration {
	per := d.spec.Timeout * time.Duration(d.spec.Retries+1)
	return max(d.spec.PollInterval, 10*per)
}

func (d *device) discover(c *snmp.Client, now func() time.Time) (*Discovery, error) {
	disc := &Discovery{
		Time:         now().UTC(),
		Capabilities: []string{},
		Scalars:      map[string]string{},
		Columns:      map[string]map[string]string{},
		Tables:       map[string]*TableDiscovery{},
		Sources:      map[string]string{},
	}

	// 1. Capabilities: those without detect always apply, the others when
	// every detect subtree exists on the agent.
	var active []*config.Capability
	for _, cp := range d.spec.Capabilities {
		ok, err := detect(c, cp)
		if err != nil {
			return nil, err // already names the OID; usually the agent being unreachable
		}
		if !ok {
			d.log.Debug("capability not detected", "capability", cp.Name)
			continue
		}
		active = append(active, cp)
		disc.Capabilities = append(disc.Capabilities, cp.Name)
	}

	// Every OID is fetched once, whatever the number of names using it.
	scalars := map[string][]string{} // oid -> names
	columns := map[string][]string{}
	for _, cp := range active {
		for name, oid := range cp.Discovery.Scalars {
			if !slices.Contains(scalars[oid], name) {
				scalars[oid] = append(scalars[oid], name)
			}
		}
		for name, oid := range cp.Discovery.Columns {
			if !slices.Contains(columns[oid], name) {
				columns[oid] = append(columns[oid], name)
			}
		}
	}

	// 2. Scalars, in one chunked GET, with the candidate oids of polled
	// scalars.
	get := map[string]bool{}
	for oid := range scalars {
		get[oid] = true
	}
	for _, cp := range active {
		for _, sc := range cp.Scalars {
			for _, oid := range sc.OIDs {
				get[oid] = true
			}
		}
	}
	pdus, err := c.Get(slices.Sorted(maps.Keys(get)))
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, p := range pdus {
		if v, ok := snmp.Convert(p); ok {
			has[p.Name] = true
			for _, name := range scalars[p.Name] {
				disc.Scalars[name] = v.String()
			}
		}
	}
	// The first candidate the agent has is polled until the next discovery.
	for _, cp := range active {
		for _, sc := range cp.Scalars {
			if len(sc.OIDs) == 0 {
				continue
			}
			for _, oid := range sc.OIDs {
				if has[oid] {
					disc.Sources[sc.Name] = oid
					break
				}
			}
			d.log.Debug("scalar source selected", "scalar", sc.Name, "oid", disc.Sources[sc.Name])
		}
	}

	// 3. Columns, walked.
	for _, root := range slices.Sorted(maps.Keys(columns)) {
		vals := map[string]string{}
		err := c.Walk(root, func(p gosnmp.SnmpPDU) error {
			idx, ok := snmp.Index(root, p.Name)
			if !ok {
				return nil
			}
			if v, ok := snmp.Convert(p); ok {
				vals[idx] = v.String()
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		for _, name := range columns[root] {
			disc.Columns[name] = vals
		}
	}

	// 4. Row selection of labelled tables, fixed until the next discovery.
	for _, cp := range active {
		for i := range cp.Tables {
			t := &cp.Tables[i]
			if t.Label == "" {
				continue
			}
			td, err := d.selectRows(c, t, disc)
			if err != nil {
				return nil, fmt.Errorf("table %s: %w", t.Name, err)
			}
			disc.Tables[t.Name] = td
		}
	}
	return disc, nil
}

func detect(c *snmp.Client, cp *config.Capability) (bool, error) {
	for _, oid := range cp.Detect {
		ok, err := c.Has(oid)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// selectRows applies the include patterns to the label of every row and,
// for high_capacity tables, decides which rows use hc_oid: the device must
// not be SNMPv1, the agent must answer the probe for the first row, and the
// row speed must be above the threshold.
func (d *device) selectRows(c *snmp.Client, t *config.TableSpec, disc *Discovery) (*TableDiscovery, error) {
	names := disc.Columns[t.Label]
	all := make([]string, 0, len(names))
	for idx := range names {
		all = append(all, idx)
	}
	sortIndexes(all)
	td := &TableDiscovery{Rows: []string{}}
	for _, idx := range all {
		if t.Selects(names[idx]) {
			td.Rows = append(td.Rows, idx)
		}
	}
	// SNMPv1 cannot carry Counter64 (RFC 3584): agents hide 64-bit counters.
	if hc := t.HighCapacity; hc != nil && len(all) > 0 && d.spec.SNMP.Version != config.Version1 {
		pdus, err := c.Get([]string{hc.Probe + "." + all[0]})
		if err != nil {
			return nil, fmt.Errorf("high_capacity probe: %w", err)
		}
		td.HighCapacity = len(pdus) > 0
		if td.HighCapacity {
			for _, idx := range td.Rows {
				speed, err := strconv.ParseUint(disc.Columns[hc.Speed][idx], 10, 64)
				if err == nil && speed > hc.Above {
					td.HighCapacityRows = append(td.HighCapacityRows, idx)
				}
			}
		}
	}
	d.log.Debug("table rows selected", "table", t.Name, "selected", len(td.Rows), "total", len(all),
		"high_capacity", td.HighCapacity, "high_capacity_rows", len(td.HighCapacityRows))
	return td, nil
}

// active returns the device's capabilities found by discovery.
func (d *device) active(disc *Discovery) []*config.Capability {
	var caps []*config.Capability
	for _, cp := range d.spec.Capabilities {
		if slices.Contains(disc.Capabilities, cp.Name) {
			caps = append(caps, cp)
		}
	}
	return caps
}

// collect polls every metric of the device's capabilities. missing counts
// requested OIDs the agent did not return (wrong OID, row gone, unsupported
// MIB).
func (d *device) collect(c *snmp.Client, store *state.Store, disc *Discovery, now func() time.Time) (batch *output.Batch, missing int, err error) {
	st, err := store.Load(d.spec.ID)
	if err != nil {
		d.log.Warn("state reset", "err", err)
	}
	batch = &output.Batch{
		DeviceID:     d.spec.ID,
		Address:      d.spec.Address,
		Capabilities: disc.Capabilities,
		Discovery:    disc.Scalars,
	}
	em := emitter{batch: batch, state: st, log: d.log, deltas: map[string]delta{}}
	caps := d.active(disc)

	// Scalars and labelled tables: one chunked GET for everything.
	type target struct {
		cap    *config.Capability
		table  *config.TableSpec
		column *config.Column
		scalar *config.Scalar
		index  string
	}
	// Several metrics may share an OID: it is fetched once and emitted for each.
	var oids []string
	targets := map[string][]target{}
	add := func(oid string, tg target) {
		if _, ok := targets[oid]; !ok {
			oids = append(oids, oid)
		}
		targets[oid] = append(targets[oid], tg)
	}
	for _, cp := range caps {
		for i := range cp.Scalars {
			sc := &cp.Scalars[i]
			oid := sc.OID
			if len(sc.OIDs) > 0 {
				oid = disc.Sources[sc.Name] // empty: the agent has none of them
			}
			if oid != "" {
				add(oid, target{cap: cp, scalar: sc})
			}
		}
		for i := range cp.Tables {
			t := &cp.Tables[i]
			td := disc.Tables[t.Name]
			if t.Label == "" || td == nil {
				continue
			}
			hcRows := make(map[string]bool, len(td.HighCapacityRows))
			for _, idx := range td.HighCapacityRows {
				hcRows[idx] = true
			}
			for _, idx := range td.Rows {
				hc := hcRows[idx]
				for j := range t.Columns {
					col := &t.Columns[j]
					base := col.OID
					if hc && col.HCOID != "" {
						base = col.HCOID
					}
					if base == "" {
						continue // formula, or hc_oid only on a row that is not high-capacity
					}
					add(base+"."+idx, target{table: t, column: col, index: idx})
				}
			}
		}
	}
	pdus, err := c.Get(oids)
	if err != nil {
		return nil, 0, err
	}
	missing = len(oids) - len(pdus)
	if missing > 0 && d.log.Enabled(context.Background(), slog.LevelDebug) {
		got := make(map[string]bool, len(pdus))
		for _, p := range pdus {
			got[p.Name] = true
		}
		var names []string
		for _, oid := range oids {
			if !got[oid] && len(names) < 10 {
				names = append(names, oid)
			}
		}
		d.log.Debug("oids not returned by agent", "count", missing, "first", names)
	}
	ts := now()
	fv := newFormulaValues(caps)
	for _, p := range pdus {
		v, ok := snmp.Convert(p)
		if !ok {
			continue
		}
		for _, tg := range targets[p.Name] {
			if tg.scalar != nil {
				fv.scalar(tg.cap, tg.scalar.Name, v)
				if tg.scalar.Emitted() {
					em.emit(p.Name, tg.scalar.Name, "", "", nil, tg.scalar.Modes, tg.scalar.Unit, v, ts)
				}
				continue
			}
			fv.column(tg.table, tg.index, tg.column.Name, v, ts)
			if tg.column.Emitted() {
				em.emit(p.Name, tg.column.Name, tg.table.Name, tg.index, labels(tg.table, tg.index, disc),
					tg.column.Modes, tg.column.Unit, v, ts)
			}
		}
	}

	// Unlabelled tables: walk each column once, filter on the index of each
	// table using it.
	type walked struct {
		table  *config.TableSpec
		column *config.Column
	}
	walks := map[string][]walked{}
	for _, cp := range caps {
		for i := range cp.Tables {
			t := &cp.Tables[i]
			if t.Label != "" {
				continue
			}
			for j := range t.Columns {
				col := &t.Columns[j]
				if col.OID != "" { // not a formula
					walks[col.OID] = append(walks[col.OID], walked{table: t, column: col})
				}
			}
		}
	}
	for _, root := range slices.Sorted(maps.Keys(walks)) {
		err := c.Walk(root, func(p gosnmp.SnmpPDU) error {
			idx, ok := snmp.Index(root, p.Name)
			if !ok {
				return nil
			}
			v, ok := snmp.Convert(p)
			if !ok {
				return nil
			}
			ts := now()
			for _, w := range walks[root] {
				if !w.table.Selects(idx) {
					continue
				}
				fv.column(w.table, idx, w.column.Name, v, ts)
				if w.column.Emitted() {
					em.emit(p.Name, w.column.Name, w.table.Name, idx, labels(w.table, idx, disc),
						w.column.Modes, w.column.Unit, v, ts)
				}
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}

	// Formulas, once every value of the poll is known.
	for _, cp := range caps {
		if env := fv.scalars[cp]; env != nil {
			for i := range cp.Scalars {
				if sc := &cp.Scalars[i]; sc.Expr != nil {
					em.compute(env, sc.Expr, sc.Name, "", "", nil, sc.Unit, sc.Emitted(), ts)
				}
			}
		}
		for i := range cp.Tables {
			t := &cp.Tables[i]
			rows := fv.rows[t]
			for _, idx := range slices.SortedFunc(maps.Keys(rows), compareOID) {
				r := rows[idx]
				for j := range t.Columns {
					if col := &t.Columns[j]; col.Expr != nil {
						em.compute(r.vals, col.Expr, col.Name, t.Name, idx, labels(t, idx, disc), col.Unit, col.Emitted(), r.time)
					}
				}
			}
		}
	}

	if err := st.Save(); err != nil {
		d.log.Warn("state save failed", "err", err)
	}
	return batch, missing, nil
}

// formulaValues collects the numeric values of one poll that formulas read:
// scalars per capability, columns per table row. Only capabilities and
// tables that have formulas are tracked.
type formulaValues struct {
	scalars map[*config.Capability]map[string]*big.Rat
	rows    map[*config.TableSpec]map[string]*formulaRow
}

type formulaRow struct {
	vals map[string]*big.Rat
	time time.Time // when the last value of the row was received
}

func newFormulaValues(caps []*config.Capability) *formulaValues {
	fv := &formulaValues{
		scalars: map[*config.Capability]map[string]*big.Rat{},
		rows:    map[*config.TableSpec]map[string]*formulaRow{},
	}
	for _, cp := range caps {
		if cp.HasScalarFormulas() {
			fv.scalars[cp] = map[string]*big.Rat{}
		}
		for i := range cp.Tables {
			if t := &cp.Tables[i]; t.HasFormulas {
				fv.rows[t] = map[string]*formulaRow{}
			}
		}
	}
	return fv
}

func (fv *formulaValues) scalar(cp *config.Capability, name string, v snmp.Value) {
	if env := fv.scalars[cp]; env != nil {
		if r, ok := ratOf(v); ok {
			env[name] = r
		}
	}
}

func (fv *formulaValues) column(t *config.TableSpec, idx, name string, v snmp.Value, ts time.Time) {
	rows := fv.rows[t]
	if rows == nil {
		return
	}
	r := rows[idx]
	if r == nil {
		r = &formulaRow{vals: map[string]*big.Rat{}}
		rows[idx] = r
	}
	if ts.After(r.time) {
		r.time = ts
	}
	if x, ok := ratOf(v); ok {
		r.vals[name] = x
	}
}

// ratOf converts a numeric value exactly. Strings, NaN and infinities are
// not numbers.
func ratOf(v snmp.Value) (*big.Rat, bool) {
	switch v.Kind {
	case snmp.KindCounter32, snmp.KindCounter64, snmp.KindUnsigned:
		return new(big.Rat).SetUint64(v.Uint), true
	case snmp.KindInteger:
		return new(big.Rat).SetInt64(v.Int), true
	case snmp.KindFloat:
		if math.IsNaN(v.Float) || math.IsInf(v.Float, 0) {
			return nil, false
		}
		return new(big.Rat).SetFloat64(v.Float), true
	}
	return nil, false
}

func labels(t *config.TableSpec, idx string, disc *Discovery) map[string]string {
	if t.Label == "" && len(t.Labels) == 0 {
		return nil
	}
	l := make(map[string]string, len(t.Labels)+1)
	if t.Label != "" {
		l[t.Label] = disc.Columns[t.Label][idx]
	}
	for _, name := range t.Labels {
		if v, ok := disc.Columns[name][idx]; ok {
			l[name] = v
		}
	}
	return l
}

type emitter struct {
	batch *output.Batch
	state *state.Device
	log   *slog.Logger
	// deltas caches this poll's delta of every OID: previous values are
	// stored per OID, and every metric reading that OID shares them.
	deltas map[string]delta
}

type delta struct {
	volume, seconds float64
	ok              bool
}

// emit adds the samples of one value read from oid: one per mode. Rate and
// volume come from the same delta.
func (e *emitter) emit(oid, metric, table, idx string, labels map[string]string,
	modes []config.Mode, unit string, v snmp.Value, ts time.Time,
) {
	sample := output.Sample{Metric: metric, Table: table, Index: idx, Labels: labels, Type: v.Type, Unit: unit, Time: ts}
	needDelta := false
	for _, m := range modes {
		if m == config.ModeRaw {
			s := sample
			s.Mode, s.Value = m, v.Raw()
			e.batch.Samples = append(e.batch.Samples, s)
		} else {
			needDelta = true
		}
	}
	if !needDelta {
		return
	}
	if !v.Numeric() {
		e.log.Debug("rate/volume skipped: value is not numeric", "metric", metric, "index", idx, "type", v.Type)
		return
	}
	dl, seen := e.deltas[oid]
	if !seen {
		dl.volume, dl.seconds, dl.ok = e.state.Delta(oid, v, ts)
		e.deltas[oid] = dl
	}
	if !dl.ok {
		return
	}
	vol, secs := dl.volume, dl.seconds
	for _, m := range modes {
		s := sample
		s.Mode = m
		switch m {
		case config.ModeVolume:
			s.Value = vol
		case config.ModeRate:
			s.Value = vol / secs
			if unit != "" {
				s.Unit = unit + "/s"
			}
		default:
			continue
		}
		e.batch.Samples = append(e.batch.Samples, s)
	}
}

// compute evaluates a formula over env, the values of its scalars or row,
// and stores the result in env for the formulas below it. A formula whose
// inputs are missing, or that divides by zero, gives no sample.
func (e *emitter) compute(env map[string]*big.Rat, f *config.Formula, metric, table, idx string,
	labels map[string]string, unit string, emitted bool, ts time.Time,
) {
	r, err := f.Eval(func(name string) (*big.Rat, bool) { v, ok := env[name]; return v, ok })
	if err != nil {
		e.log.Debug("formula not computed", "metric", metric, "table", table, "index", idx, "reason", err)
		return
	}
	env[metric] = r
	if !emitted {
		return
	}
	e.batch.Samples = append(e.batch.Samples, output.Sample{
		Metric: metric, Table: table, Index: idx, Labels: labels, Mode: config.ModeRaw,
		Type: output.TypeFormula, Unit: unit, Value: f.Value(r), Time: ts,
	})
}

func rowCount(d *Discovery) int {
	n := 0
	for _, t := range d.Tables {
		n += len(t.Rows)
	}
	return n
}

// sortIndexes orders OID suffixes numerically, component by component.
func sortIndexes(idx []string) {
	sort.Slice(idx, func(i, j int) bool { return lessOID(idx[i], idx[j]) })
}

func compareOID(a, b string) int {
	switch {
	case lessOID(a, b):
		return -1
	case lessOID(b, a):
		return 1
	}
	return 0
}

func lessOID(a, b string) bool {
	for a != "" && b != "" {
		var x, y uint64
		var i, j int
		for i < len(a) && a[i] != '.' {
			x = x*10 + uint64(a[i]-'0')
			i++
		}
		for j < len(b) && b[j] != '.' {
			y = y*10 + uint64(b[j]-'0')
			j++
		}
		if x != y {
			return x < y
		}
		a, b = trimDot(a[i:]), trimDot(b[j:])
	}
	return a == "" && b != ""
}

func trimDot(s string) string {
	if s != "" && s[0] == '.' {
		return s[1:]
	}
	return s
}
