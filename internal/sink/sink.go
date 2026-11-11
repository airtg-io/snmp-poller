// Package sink sends polled samples to time series databases: Prometheus
// remote write receivers and InfluxDB 3.
//
// Every sink works on its own: Write encodes a device's batch and returns
// at once; batches are grouped into requests sent by the sink's own
// goroutine, so a slow or unreachable destination never delays polling or
// the other sinks. What a destination does not accept yet waits in a FIFO:
// in memory, then on disk (<data_dir>/sinks/<id>) while the destination is
// unreachable, up to disk_buffer bytes, the oldest data being dropped first.
package sink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// Sample is one emitted value.
type Sample struct {
	// Capability is the name of the capability defining the metric.
	Capability string
	// Metric is the scalar name, or the table column name.
	Metric string
	// Table is the table name; empty for scalars.
	Table string
	// Index is the row index (OID suffix) for table samples; empty for scalars.
	Index string
	// Labels are the discovery values of the table's label and labels
	// columns for the row (e.g. ifDescr, ifName).
	Labels map[string]string
	// Mode is raw, rate or volume.
	Mode config.Mode
	// Type is the SNMP type name of the polled value (e.g. Counter64), or
	// TypeFormula for a value computed by a formula.
	Type string
	// Unit is the unit configured for the metric (e.g. bytes, percent),
	// with "/s" appended for rates; empty when not configured.
	Unit string
	// Value is the sample value: for raw mode an int64, uint64, float64 or
	// string depending on the SNMP type; for rate and volume a float64; for
	// a formula an int64 or a float64 (see config.Formula).
	Value any
	// Time is when the value was received.
	Time time.Time
}

// TypeFormula is the Type of samples computed by a formula.
const TypeFormula = "Formula"

// Batch is every sample produced by one poll of one device.
type Batch struct {
	DeviceID string
	Address  string
	// Interval is the device's poll interval.
	Interval time.Duration
	// DiscoveredAt is when the discovery the batch was polled with ran.
	DiscoveredAt time.Time
	// Capabilities are the names of the capabilities found on the device.
	Capabilities []string
	// Discovery holds the device's discovery scalars (sysDescr, sysName, ...).
	Discovery map[string]string
	// Columns holds the device's discovery columns: name -> index -> value.
	Columns map[string]map[string]string
	Samples []Sample
}

// Stats are a sink's counters since the previous call to Stats, and its
// current backlog.
type Stats struct {
	Sent, Requests, Failures, Dropped int64
	// Backlog is what waits to be sent: samples, and bytes on disk.
	BacklogSamples, BacklogBytes int64
	Down                         bool
}

// memoryLimit is the size of encoded requests a sink keeps in memory:
// beyond it, or while the destination is unreachable, requests go to the
// disk buffer, or are dropped (oldest first) without one.
const memoryLimit = 32 << 20

// maxPending bounds the samples encoded but not yet grouped into a request,
// should the encoding fall behind.
const maxPending = 64 << 20

// Retry delays while the destination is down: doubled from retryMin up
// to retryMax. Variables for tests.
var (
	retryMin = time.Second
	retryMax = 30 * time.Second
)

// pendingUnit is a unit of the pending buffer, with when it was written.
type pendingUnit struct {
	unit
	written time.Time
}

// Sink is one configured destination.
type Sink struct {
	cfg     config.Sink
	log     *slog.Logger
	enc     encoder
	client  transport
	dataDir string
	fifo    *fifo

	mu        sync.Mutex
	pending   []byte        // encoded samples not yet in a request
	units     []pendingUnit // the units of pending, in order
	nPending  int
	closed    bool
	started   bool
	inherited bool // the disk buffer comes from the sink this one replaces

	kick       chan struct{}
	stop       chan struct{} // closed by Close: intake flushes and exits
	intakeDone chan struct{}
	senderDone chan struct{}
	stopSend   context.CancelFunc
	sendCtx    context.Context

	sent, requests, failures, dropped atomic.Int64
	lastDropLog                       atomic.Int64 // unix nanos
}

// New validates what a sink needs to run (TLS files, ...) without touching
// the disk: -check uses it. Open and Start follow.
func New(cfg config.Sink, dataDir string, log *slog.Logger) (*Sink, error) {
	var c transport
	if cfg.Type == config.SinkAirtg {
		cfg.URL = AnalyzerURL // fixed: logged as the sink's destination
		c = &natsClient{url: cfg.URL, timeout: cfg.Timeout}
	} else {
		hc, err := newClient(&cfg)
		if err != nil {
			return nil, err
		}
		c = hc
	}
	s := &Sink{
		cfg:        cfg,
		log:        log.With("sink", cfg.ID),
		client:     c,
		dataDir:    dataDir,
		kick:       make(chan struct{}, 1),
		stop:       make(chan struct{}),
		intakeDone: make(chan struct{}),
		senderDone: make(chan struct{}),
	}
	switch cfg.Type {
	case config.SinkPrometheus:
		s.enc = &promEncoder{sink: &s.cfg}
	case config.SinkInfluxDB:
		s.enc = &influxEncoder{sink: &s.cfg}
	case config.SinkAirtg:
		s.enc = newAirtgEncoder()
	default:
		return nil, fmt.Errorf("unknown sink type %q", cfg.Type)
	}
	s.sendCtx, s.stopSend = context.WithCancel(context.Background())
	return s, nil
}

// Dir returns the disk buffer directory of a sink.
func Dir(dataDir, id string) string { return filepath.Join(dataDir, config.SinksDir, id) }

// Open opens the disk buffer: with disk_buffer set, or to send what a
// previous run left in it.
func (s *Sink) Open() error {
	dq, shared, err := acquire(Dir(s.dataDir, s.cfg.ID), s.cfg.DiskBuffer.Bytes > 0, s.log)
	s.inherited = shared
	if err != nil {
		return fmt.Errorf("sink %q: disk buffer: %w", s.cfg.ID, err)
	}
	s.fifo = newFIFO(dq, s.cfg.DiskBuffer.Bytes, s.log)
	return nil
}

// Start starts sending. The sink becomes the reader of its disk buffer:
// a sink it replaces (reload) only appends to it from then on.
func (s *Sink) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.started || s.fifo == nil {
		return
	}
	s.started = true
	s.fifo.own()
	if n := s.fifo.backlog(); n > 0 {
		msg := "sink: sending the disk buffer left by a previous run first"
		if s.inherited {
			msg = "sink: sending the backlog of the sink it replaces first"
		}
		s.log.Info(msg, "samples", n)
	}
	go func() { defer close(s.intakeDone); s.intake() }()
	go func() { defer close(s.senderDone); s.sender() }()
}

// ID returns the sink id.
func (s *Sink) ID() string { return s.cfg.ID }

// Write encodes the samples of b this sink sends and queues them. It never
// blocks on the destination.
func (s *Sink) Write(b *Batch) {
	buf, units, n := s.enc.encode(nil, b, nil)
	if len(units) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		s.drop(n, "sink closed")
		return
	case len(s.pending) > maxPending:
		s.mu.Unlock()
		s.drop(n, "encoding queue full")
		return
	}
	first := s.nPending == 0
	base := len(s.pending)
	s.pending = append(s.pending, buf...)
	for _, u := range units {
		u.end += base
		s.units = append(s.units, pendingUnit{unit: u, written: now})
	}
	s.nPending += n
	full := s.nPending >= s.cfg.BatchSize
	s.mu.Unlock()
	if first || full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

// drop counts lost samples, logging at most one warning a minute.
func (s *Sink) drop(n int, why string) {
	s.dropped.Add(int64(n))
	now := time.Now().UnixNano()
	if last := s.lastDropLog.Load(); now-last >= int64(time.Minute) && s.lastDropLog.CompareAndSwap(last, now) {
		s.log.Warn("sink: samples dropped", "samples", n, "reason", why)
	}
}

// intake groups pending samples into requests of at most batch_size
// samples (an InfluxDB line is never split: a line of more samples is a
// request of its own): a request is cut when it is full, or flush_interval
// after its oldest sample was written.
func (s *Sink) intake() {
	t := time.NewTimer(s.cfg.FlushInterval)
	defer t.Stop()
	for {
		stopping := false
		select {
		case <-s.kick:
		case <-t.C:
		case <-s.stop:
			stopping = true
		}
		s.mu.Lock()
		reqs := s.cut(stopping)
		wait := s.cfg.FlushInterval
		if len(s.units) > 0 {
			wait = max(s.cfg.FlushInterval-time.Since(s.units[0].written), time.Millisecond)
		}
		s.mu.Unlock()
		for _, r := range reqs {
			if dropped := s.fifo.push(record{kind: s.enc.kind(), samples: r.samples, data: s.enc.finish(r.body)}); dropped > 0 {
				s.drop(dropped, "buffer full")
			}
		}
		if stopping {
			return
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(wait)
	}
}

type request struct {
	body    []byte
	samples int
}

// cut takes the requests to send off the pending buffer: every full one,
// and the rest when all is true or its oldest sample is flush_interval old.
// Called with s.mu held.
func (s *Sink) cut(all bool) []request {
	var reqs []request
	i, start := 0, 0 // first unit and byte not taken
	for i < len(s.units) {
		j, n := i, 0
		for j < len(s.units) && (j == i || n+s.units[j].samples <= s.cfg.BatchSize) {
			n += s.units[j].samples
			j++
		}
		full := j < len(s.units) || n >= s.cfg.BatchSize
		if !full && !all && time.Since(s.units[i].written) < s.cfg.FlushInterval {
			break
		}
		end := s.units[j-1].end
		reqs = append(reqs, request{body: s.pending[start:end], samples: n})
		s.nPending -= n
		i, start = j, end
	}
	if i == 0 {
		return nil
	}
	// The requests keep the old array: what is left moves to a new one, so
	// that Write never appends over a request.
	if i == len(s.units) {
		s.pending, s.units = nil, nil
		return reqs
	}
	s.pending = append([]byte(nil), s.pending[start:]...)
	units := make([]pendingUnit, len(s.units)-i)
	for k := range units {
		units[k] = s.units[i+k]
		units[k].end -= start
	}
	s.units = units
	return reqs
}

// sender posts the head of the FIFO until the sink is closed.
func (s *Sink) sender() {
	ctx := s.sendCtx
	backoff := retryMin
	down := false
	var downSince time.Time
	for {
		r, ok := s.fifo.head(ctx)
		if !ok {
			return
		}
		if r.kind != s.enc.kind() {
			s.fifo.pop(r.seq)
			s.drop(r.samples, "disk buffer written by a sink of another type")
			continue
		}
		s.requests.Add(1)
		err := s.client.post(ctx, r.data)
		var perm *permanentError
		switch {
		case err == nil:
			s.fifo.pop(r.seq)
			s.sent.Add(int64(r.samples))
			if down {
				down = false
				s.fifo.setDown(false)
				s.log.Info("sink: destination reachable again", "down_for", time.Since(downSince).Round(time.Second),
					"backlog_samples", s.fifo.backlog())
			}
			backoff = retryMin
		case ctx.Err() != nil:
			return
		case errors.As(err, &perm):
			s.failures.Add(1)
			s.fifo.pop(r.seq)
			s.drop(r.samples, "rejected by the destination: "+perm.Error())
		default:
			s.failures.Add(1)
			if !down {
				down, downSince = true, time.Now()
				s.fifo.setDown(true)
				msg := "sink: destination unreachable, data is kept in the disk buffer until it is back"
				if !s.fifo.hasDisk() {
					msg = "sink: destination unreachable, data is kept in memory (no disk buffer) until it is back"
				}
				s.log.Warn(msg, "url", s.cfg.URL, "err", err)
			} else {
				s.log.Debug("sink: send failed", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, retryMax)
		}
	}
}

// Stats returns the counters since the previous call and the backlog.
func (s *Sink) Stats() Stats {
	st := Stats{
		Sent:     s.sent.Swap(0),
		Requests: s.requests.Swap(0),
		Failures: s.failures.Swap(0),
		Dropped:  s.dropped.Swap(0),
	}
	s.mu.Lock()
	st.BacklogSamples = int64(s.nPending)
	s.mu.Unlock()
	if s.fifo != nil {
		st.BacklogSamples += s.fifo.backlog()
		st.BacklogBytes = s.fifo.diskBytes()
		st.Down = s.fifo.isDown()
	}
	return st
}

// Close flushes pending samples and gives the sender up to the sink
// timeout to send what is in memory, unless the destination is down. What
// is left goes to the disk buffer, or is dropped without one.
func (s *Sink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	started := s.started
	s.mu.Unlock()
	if !started {
		s.stopSend()
		if s.fifo != nil {
			s.fifo.close()
		}
		return nil
	}
	close(s.stop)
	<-s.intakeDone // pending samples are in the FIFO
	deadline := time.Now().Add(s.cfg.Timeout)
	for time.Now().Before(deadline) && s.fifo.memoryLen() > 0 && !s.fifo.isDown() {
		time.Sleep(20 * time.Millisecond)
	}
	s.stopSend()
	<-s.senderDone
	if lost := s.fifo.close(); lost > 0 {
		s.dropped.Add(int64(lost))
		s.log.Warn("sink: samples not sent before stopping (no disk buffer)", "samples", lost)
	}
	s.client.close()
	return nil
}

// numeric returns a sample value as a float64; ok is false for strings,
// NaN and infinities.
func numeric(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case int64:
		f = float64(x)
	case uint64:
		f = float64(x)
	case float64:
		f = x
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0)
}

// tagValue is one tag of a sample.
type tagValue struct{ name, value string }

// tags returns the tags of a sample, sorted by name, the first source of
// a name winning; empty values are left out.
func tags(cfg *config.Sink, b *Batch, smp *Sample, dst []tagValue) []tagValue {
	add := func(name, value string) {
		if strings.TrimRight(value, "\\") == "" || slices.ContainsFunc(dst, func(t tagValue) bool { return t.name == name }) {
			return
		}
		dst = append(dst, tagValue{name, value})
	}
	for _, t := range cfg.ResolvedTags {
		switch t.Kind {
		case config.KindDevice:
			add(t.Name, b.DeviceID)
		case config.KindAddress:
			add(t.Name, b.Address)
		case config.KindIndex:
			add(t.Name, smp.Index)
		case config.KindTable:
			add(t.Name, smp.Table)
		case config.KindCapability:
			add(t.Name, smp.Capability)
		case config.KindLabels:
			for _, k := range sortedKeys(smp.Labels) {
				add(k, smp.Labels[k])
			}
		case config.KindScalar:
			add(t.Name, b.Discovery[t.Source])
		case config.KindColumn:
			if smp.Table != "" && slices.Contains(t.Capabilities, smp.Capability) {
				add(t.Name, b.Columns[t.Source][smp.Index])
			}
		}
	}
	slices.SortFunc(dst, func(a, b tagValue) int {
		switch {
		case a.name < b.name:
			return -1
		case a.name > b.name:
			return 1
		}
		return 0
	})
	return dst
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
