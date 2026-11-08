package poller

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
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

	// 2. Scalars, in one chunked GET.
	oids := slices.Sorted(maps.Keys(scalars))
	pdus, err := c.Get(oids)
	if err != nil {
		return nil, err
	}
	for _, p := range pdus {
		if v, ok := snmp.Convert(p); ok {
			for _, name := range scalars[p.Name] {
				disc.Scalars[name] = v.String()
			}
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
			add(cp.Scalars[i].OID, target{scalar: &cp.Scalars[i]})
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
						continue // hc_oid only, on a row that is not high-capacity
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
	for _, p := range pdus {
		v, ok := snmp.Convert(p)
		if !ok {
			continue
		}
		for _, tg := range targets[p.Name] {
			if tg.scalar != nil {
				em.emit(p.Name, tg.scalar.Name, "", "", nil, tg.scalar.Modes, v, ts)
				continue
			}
			em.emit(p.Name, tg.column.Name, tg.table.Name, tg.index, labels(tg.table, tg.index, disc),
				tg.column.Modes, v, ts)
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
				walks[col.OID] = append(walks[col.OID], walked{table: t, column: col})
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
				if w.table.Selects(idx) {
					em.emit(p.Name, w.column.Name, w.table.Name, idx, labels(w.table, idx, disc), w.column.Modes, v, ts)
				}
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}

	if err := st.Save(); err != nil {
		d.log.Warn("state save failed", "err", err)
	}
	return batch, missing, nil
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
	modes []config.Mode, v snmp.Value, ts time.Time,
) {
	sample := output.Sample{Metric: metric, Table: table, Index: idx, Labels: labels, Type: v.Type, Time: ts}
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
		default:
			continue
		}
		e.batch.Samples = append(e.batch.Samples, s)
	}
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
