package poller

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/snmp"
	"github.com/airtg-io/snmp-poller/internal/state"
)

// Discovery is the result of a discovery run on one device.
type Discovery struct {
	Time    time.Time         `json:"time"`
	Scalars map[string]string `json:"scalars"`
	// Columns maps a discovery column name to index -> value.
	Columns map[string]map[string]string `json:"columns"`
	// Rows maps a table name to its selected row indexes, in OID order.
	Rows map[string][]string `json:"rows"`
}

// device is the runtime state of one configured device. Fields are only
// touched by the worker currently polling it (the scheduler guarantees at
// most one poll per device at a time).
type device struct {
	spec    config.DeviceSpec
	log     *slog.Logger
	outputs []output.Output

	discovery    *Discovery
	discoveredAt time.Time
	failing      bool
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

	c, err := snmp.Dial(ctx, &d.spec)
	if err != nil {
		return res, err
	}
	defer c.Close()

	if d.discovery == nil || now().Sub(d.discoveredAt) >= d.spec.DiscoveryInterval {
		res.discovered = true
		start := now()
		disc, err := d.discover(c, now)
		if err != nil {
			res.discoveryErr = true
			return res, fmt.Errorf("discovery: %w", err)
		}
		// Row indexes may have changed: previous values are meaningless.
		if err := store.ResetDevice(d.spec.ID); err != nil {
			return res, fmt.Errorf("reset state: %w", err)
		}
		if err := store.SaveDiscovery(d.spec.ID, disc); err != nil {
			return res, fmt.Errorf("save discovery: %w", err)
		}
		d.discovery, d.discoveredAt = disc, start
		d.log.Debug("discovery done", "duration", roundDur(now().Sub(start)),
			"scalars", len(disc.Scalars), "columns", len(disc.Columns), "rows", rowCount(disc))
	}

	batch, missing, err := d.collect(c, store, now)
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

// deadline bounds a whole poll so a stuck device cannot hold a worker forever.
func (d *device) deadline() time.Duration {
	per := d.spec.Timeout * time.Duration(d.spec.Retries+1)
	return max(d.spec.PollInterval, 10*per)
}

func (d *device) discover(c *snmp.Client, now func() time.Time) (*Discovery, error) {
	disc := &Discovery{
		Time:    now(),
		Scalars: map[string]string{},
		Columns: map[string]map[string]string{},
		Rows:    map[string][]string{},
	}

	names := make([]string, 0, len(d.spec.Discovery.Scalars))
	byOID := map[string]string{}
	oids := make([]string, 0, len(names))
	for name, oid := range d.spec.Discovery.Scalars {
		names = append(names, name)
		byOID[oid] = name
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	pdus, err := c.Get(oids)
	if err != nil {
		return nil, err
	}
	for _, p := range pdus {
		if v, ok := snmp.Convert(p); ok {
			disc.Scalars[byOID[p.Name]] = v.String()
		}
	}

	colNames := make([]string, 0, len(d.spec.Discovery.Columns))
	for name := range d.spec.Discovery.Columns {
		colNames = append(colNames, name)
	}
	sort.Strings(colNames)
	for _, name := range colNames {
		root := d.spec.Discovery.Columns[name]
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
		disc.Columns[name] = vals
	}

	// Row selection for labelled tables is fixed until the next discovery.
	for _, t := range d.spec.Tables {
		if t.Label == "" {
			continue
		}
		var rows []string
		for idx, label := range disc.Columns[t.Label] {
			if t.Selects(label) {
				rows = append(rows, idx)
			}
		}
		sortIndexes(rows)
		disc.Rows[t.Name] = rows
		d.log.Debug("table rows selected", "table", t.Name, "selected", len(rows),
			"total", len(disc.Columns[t.Label]))
	}
	return disc, nil
}

// collect polls every metric. missing counts requested OIDs the agent did
// not return (wrong OID, row gone, unsupported MIB).
func (d *device) collect(c *snmp.Client, store *state.Store, now func() time.Time) (batch *output.Batch, missing int, err error) {
	st, err := store.Load(d.spec.ID)
	if err != nil {
		d.log.Warn("state reset", "err", err)
	}
	batch = &output.Batch{
		DeviceID:  d.spec.ID,
		Address:   d.spec.Address,
		Discovery: d.discovery.Scalars,
	}
	em := emitter{batch: batch, state: st, log: d.log}

	// Scalars and labelled tables: one chunked GET for everything.
	type target struct {
		table  *config.TableSpec
		column *config.Column
		scalar *config.Scalar
		index  string
	}
	var oids []string
	targets := map[string]target{}
	for i := range d.spec.Scalars {
		s := &d.spec.Scalars[i]
		oids = append(oids, s.OID)
		targets[s.OID] = target{scalar: s}
	}
	for i := range d.spec.Tables {
		t := &d.spec.Tables[i]
		if t.Label == "" {
			continue
		}
		for _, idx := range d.discovery.Rows[t.Name] {
			for j := range t.Columns {
				oid := t.Columns[j].OID + "." + idx
				oids = append(oids, oid)
				targets[oid] = target{table: t, column: &t.Columns[j], index: idx}
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
		tg, ok := targets[p.Name]
		if !ok {
			continue
		}
		v, ok := snmp.Convert(p)
		if !ok {
			continue
		}
		if tg.scalar != nil {
			em.emit(tg.scalar.Name, "", "", nil, tg.scalar.Modes, v, ts)
			continue
		}
		em.emit(tg.column.Name, tg.table.Name, tg.index, d.labels(tg.table, tg.index),
			tg.column.Modes, v, ts)
	}

	// Unlabelled tables: walk each column, filter on the index.
	for i := range d.spec.Tables {
		t := &d.spec.Tables[i]
		if t.Label != "" {
			continue
		}
		for _, col := range t.Columns {
			err := c.Walk(col.OID, func(p gosnmp.SnmpPDU) error {
				idx, ok := snmp.Index(col.OID, p.Name)
				if !ok || !t.Selects(idx) {
					return nil
				}
				if v, ok := snmp.Convert(p); ok {
					em.emit(col.Name, t.Name, idx, d.labels(t, idx), col.Modes, v, now())
				}
				return nil
			})
			if err != nil {
				return nil, 0, err
			}
		}
	}

	if err := st.Save(); err != nil {
		d.log.Warn("state save failed", "err", err)
	}
	return batch, missing, nil
}

func (d *device) labels(t *config.TableSpec, idx string) map[string]string {
	if t.Label == "" && len(t.Labels) == 0 {
		return nil
	}
	l := make(map[string]string, len(t.Labels)+1)
	if t.Label != "" {
		l[t.Label] = d.discovery.Columns[t.Label][idx]
	}
	for _, name := range t.Labels {
		if v, ok := d.discovery.Columns[name][idx]; ok {
			l[name] = v
		}
	}
	return l
}

type emitter struct {
	batch *output.Batch
	state *state.Device
	log   *slog.Logger
}

func (e *emitter) emit(metric, table, idx string, labels map[string]string,
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
	key := metric
	if table != "" {
		key = table + "/" + metric + "/" + idx
	}
	vol, secs, ok := e.state.Delta(key, v, ts)
	if !ok {
		return
	}
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
	for _, r := range d.Rows {
		n += len(r)
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
