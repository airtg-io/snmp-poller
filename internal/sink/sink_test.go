package sink

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/influxdata/line-protocol/v2/lineprotocol"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/testconf"
)

func TestMain(m *testing.M) {
	retryMin, retryMax = 10*time.Millisecond, 50*time.Millisecond
	os.Exit(m.Run())
}

// Capabilities of the test configurations: scalars, a labelled table and
// discovery data.
var caps = map[string]string{
	"system": `
discovery:
  scalars: { sysName: 1.3.6.1.2.1.1.5.0, sysLocation: 1.3.6.1.2.1.1.6.0 }
scalars:
  - { name: uptime, oid: 1.3.6.1.2.1.1.3.0 }
  - { name: sysDescr, oid: 1.3.6.1.2.1.1.1.0 }
`,
	"interfaces": `
discovery:
  columns: { ifDescr: 1.3.6.1.2.1.2.2.1.2, ifAlias: 1.3.6.1.2.1.31.1.1.1.18, ifType: 1.3.6.1.2.1.2.2.1.3 }
tables:
  - name: interfaces
    label: ifDescr
    labels: [ifAlias]
    columns:
      - { name: ifInOctets, oid: 1.3.6.1.2.1.2.2.1.10, modes: [rate, volume] }
      - { name: ifOperStatus, oid: 1.3.6.1.2.1.2.2.1.8 }
`,
	"storage": `
discovery:
  columns: { hrStorageDescr: 1.3.6.1.2.1.25.2.3.1.3 }
tables:
  - name: storage
    label: hrStorageDescr
    columns: [{ name: storageUsed, oid: 1.3.6.1.2.1.25.2.3.1.6 }]
`,
}

// sinkConfig parses one sink (YAML flow mapping body) and returns it.
func sinkConfig(t testing.TB, body string) config.Sink {
	t.Helper()
	cfg := testconf.Parse(t, "sinks: [{ "+body+" }]", caps)
	return cfg.Sinks[0]
}

var t0 = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

// testBatch is one poll of a device with two interfaces and a storage row.
func testBatch(at time.Time) *Batch {
	if1 := map[string]string{"ifDescr": "eth0", "ifAlias": "uplink, to core"}
	if2 := map[string]string{"ifDescr": "eth 1"}
	return &Batch{
		DeviceID:  "r1",
		Address:   "192.0.2.1",
		Discovery: map[string]string{"sysName": "r1.example.net", "sysLocation": "Paris\nrack 4"},
		Columns: map[string]map[string]string{
			"ifDescr": {"1": "eth0", "2": "eth 1"}, "ifType": {"1": "6", "2": "6"},
			"hrStorageDescr": {"1": `C:\ Label="sys"`},
		},
		Samples: []Sample{
			{Capability: "system", Metric: "uptime", Mode: config.ModeRaw, Value: uint64(4200), Time: at},
			{Capability: "system", Metric: "sysDescr", Mode: config.ModeRaw, Value: `Linux "x"` + "\n2.6", Time: at},
			{Capability: "interfaces", Table: "interfaces", Index: "1", Labels: if1, Metric: "ifInOctets", Mode: config.ModeRate, Value: 1250.5, Time: at},
			{Capability: "interfaces", Table: "interfaces", Index: "1", Labels: if1, Metric: "ifInOctets", Mode: config.ModeVolume, Value: 75030.0, Time: at},
			{Capability: "interfaces", Table: "interfaces", Index: "1", Labels: if1, Metric: "ifOperStatus", Mode: config.ModeRaw, Value: int64(1), Time: at.Add(3 * time.Millisecond)},
			{Capability: "interfaces", Table: "interfaces", Index: "2", Labels: if2, Metric: "ifOperStatus", Mode: config.ModeRaw, Value: int64(2), Time: at},
			{Capability: "interfaces", Table: "interfaces", Index: "2", Labels: if2, Metric: "ifInOctets", Mode: config.ModeRate, Value: math.NaN(), Time: at},
			{Capability: "storage", Table: "storage", Index: "1", Labels: map[string]string{"hrStorageDescr": `C:\ Label="sys"`},
				Metric: "storageUsed", Mode: config.ModeRaw, Type: TypeFormula, Value: int64(1 << 40), Time: at},
		},
	}
}

type promSeries struct {
	labels map[string]string
	value  float64
	ts     int64
}

func (s promSeries) String() string {
	var l []string
	for _, k := range sortedKeys(s.labels) {
		l = append(l, k+"="+s.labels[k])
	}
	return fmt.Sprintf("{%s} %v @%d", strings.Join(l, " "), s.value, s.ts)
}

// decodeProm decodes a remote write request with protowire, checking that
// labels are sorted as remote write requires.
func decodeProm(t testing.TB, payload []byte) []promSeries {
	t.Helper()
	raw, err := snappy.Decode(nil, payload)
	if err != nil {
		t.Fatalf("snappy: %v", err)
	}
	var out []promSeries
	fields(t, raw, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) {
		if num != 1 || typ != protowire.BytesType {
			t.Fatalf("WriteRequest field %d type %d", num, typ)
		}
		s := promSeries{labels: map[string]string{}}
		var prev string
		fields(t, v, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) {
			switch num {
			case 1: // Label
				var name, value string
				fields(t, v, func(num protowire.Number, _ protowire.Type, v []byte, _ uint64) {
					if num == 1 {
						name = string(v)
					} else {
						value = string(v)
					}
				})
				if name <= prev {
					t.Errorf("labels not sorted: %q after %q", name, prev)
				}
				prev = name
				s.labels[name] = value
			case 2: // Sample
				fields(t, v, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) {
					switch {
					case num == 1 && typ == protowire.Fixed64Type:
						s.value = math.Float64frombits(n)
					case num == 2 && typ == protowire.VarintType:
						s.ts = int64(n)
					default:
						t.Fatalf("Sample field %d type %d", num, typ)
					}
				})
			default:
				t.Fatalf("TimeSeries field %d", num)
			}
		})
		out = append(out, s)
	})
	return out
}

func fields(t testing.TB, b []byte, fn func(protowire.Number, protowire.Type, []byte, uint64)) {
	t.Helper()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatalf("bad tag: %v", protowire.ParseError(n))
		}
		b = b[n:]
		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				t.Fatalf("bad bytes: %v", protowire.ParseError(n))
			}
			fn(num, typ, v, 0)
			b = b[n:]
		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				t.Fatal("bad fixed64")
			}
			fn(num, typ, nil, v)
			b = b[n:]
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				t.Fatal("bad varint")
			}
			fn(num, typ, nil, v)
			b = b[n:]
		default:
			t.Fatalf("unexpected wire type %d", typ)
		}
	}
}

func TestPrometheusEncoding(t *testing.T) {
	cfg := sinkConfig(t, `id: p, type: prometheus, url: "http://p/w", tags: [device, { host: sysName }, ifType, labels, index]`)
	enc := &promEncoder{sink: &cfg}
	body, n := enc.encode(nil, testBatch(t0))
	body, n2 := enc.encode(body, testBatch(t0.Add(time.Minute))) // batches concatenate
	got := decodeProm(t, enc.finish(body))
	if n != 6 || n2 != 6 || len(got) != 12 {
		t.Fatalf("encoded %d+%d samples, decoded %d: %v", n, n2, len(got), got)
	}
	var lines []string
	for _, s := range got[:6] {
		lines = append(lines, s.String())
	}
	ms := t0.UnixMilli()
	want := []string{
		fmt.Sprintf("{__name__=snmp_uptime device=r1 host=r1.example.net} 4200 @%d", ms),
		fmt.Sprintf("{__name__=snmp_ifInOctets_rate device=r1 host=r1.example.net ifAlias=uplink, to core ifDescr=eth0 ifType=6 index=1} 1250.5 @%d", ms),
		fmt.Sprintf("{__name__=snmp_ifInOctets_volume device=r1 host=r1.example.net ifAlias=uplink, to core ifDescr=eth0 ifType=6 index=1} 75030 @%d", ms),
		fmt.Sprintf("{__name__=snmp_ifOperStatus device=r1 host=r1.example.net ifAlias=uplink, to core ifDescr=eth0 ifType=6 index=1} 1 @%d", ms+3),
		fmt.Sprintf("{__name__=snmp_ifOperStatus device=r1 host=r1.example.net ifDescr=eth 1 ifType=6 index=2} 2 @%d", ms),
		// ifType is a column of interfaces: not a tag of storage rows.
		fmt.Sprintf(`{__name__=snmp_storageUsed device=r1 host=r1.example.net hrStorageDescr=C:\ Label="sys" index=1} 1.099511627776e+12 @%d`, ms),
	}
	if !slices.Equal(lines, want) {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	// Keys and prefix.
	cfg = sinkConfig(t, `id: p, type: prometheus, url: "http://p/w", prefix: "", tags: [device], keys: { include: [ifInOctets], exclude: [_volume] }`)
	enc = &promEncoder{sink: &cfg}
	body, n = enc.encode(nil, testBatch(t0))
	got = decodeProm(t, enc.finish(body))
	if n != 1 || got[0].String() != fmt.Sprintf("{__name__=ifInOctets_rate device=r1} 1250.5 @%d", ms) {
		t.Errorf("filtered: %v", got)
	}
}

type parsedLine struct {
	measurement string
	tags        map[string]string
	fields      map[string]string // kind:value
	time        time.Time
}

// decodeInflux parses line protocol with InfluxData's parser.
func decodeInflux(t testing.TB, body []byte) []parsedLine {
	t.Helper()
	dec := lineprotocol.NewDecoderWithBytes(body)
	var out []parsedLine
	for dec.Next() {
		m, err := dec.Measurement()
		if err != nil {
			t.Fatalf("measurement: %v\n%s", err, body)
		}
		l := parsedLine{measurement: string(m), tags: map[string]string{}, fields: map[string]string{}}
		for {
			k, v, err := dec.NextTag()
			if err != nil {
				t.Fatalf("tag: %v\n%s", err, body)
			}
			if k == nil {
				break
			}
			l.tags[string(k)] = string(v)
		}
		for {
			k, v, err := dec.NextField()
			if err != nil {
				t.Fatalf("field: %v\n%s", err, body)
			}
			if k == nil {
				break
			}
			l.fields[string(k)] = fmt.Sprintf("%v:%v", v.Kind(), v.Interface())
		}
		if l.time, err = dec.Time(lineprotocol.Millisecond, time.Time{}); err != nil {
			t.Fatalf("time: %v", err)
		}
		out = append(out, l)
	}
	return out
}

func gunzip(t testing.TB, b []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestInfluxEncoding(t *testing.T) {
	cfg := sinkConfig(t, `id: i, type: influxdb, url: "http://i", database: d, tags: [device, sysLocation, labels, index, { kind: ifType }]`)
	enc := &influxEncoder{sink: &cfg}
	body, n := enc.encode(nil, testBatch(t0))
	if n != 7 {
		t.Errorf("encoded %d samples, want 7 (NaN left out)", n)
	}
	got := decodeInflux(t, gunzip(t, enc.finish(body)))
	str := func(l parsedLine) string {
		var tags, fields []string
		for _, k := range sortedKeys(l.tags) {
			tags = append(tags, k+"="+l.tags[k])
		}
		for _, k := range sortedKeys(l.fields) {
			fields = append(fields, k+"="+l.fields[k])
		}
		return fmt.Sprintf("%s [%s] [%s] %s", l.measurement, strings.Join(tags, "|"), strings.Join(fields, "|"), l.time.UTC().Format(time.RFC3339Nano))
	}
	var lines []string
	for _, l := range got {
		lines = append(lines, str(l))
	}
	want := []string{
		`system [device=r1|sysLocation=Paris rack 4] [sysDescr=string:Linux "x" 2.6|uptime=int:4200] 2026-11-08T10:00:00Z`,
		// One line per row: the first timestamp of the row.
		`interfaces [device=r1|ifAlias=uplink, to core|ifDescr=eth0|index=1|kind=6|sysLocation=Paris rack 4] [ifInOctets_rate=float:1250.5|ifInOctets_volume=float:75030|ifOperStatus=int:1] 2026-11-08T10:00:00Z`,
		`interfaces [device=r1|ifDescr=eth 1|index=2|kind=6|sysLocation=Paris rack 4] [ifOperStatus=int:2] 2026-11-08T10:00:00Z`,
		`storage [device=r1|hrStorageDescr=C:\ Label="sys"|index=1|sysLocation=Paris rack 4] [storageUsed=int:1099511627776] 2026-11-08T10:00:00Z`,
	}
	if !slices.Equal(lines, want) {
		t.Errorf("got:\n%s\nwant:\n%s\nbody:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"), gunzip(t, enc.finish(body)))
	}

	// Values: integer types are all "i" fields; huge uint64, NaN and Inf are left out.
	for v, want := range map[any]string{int64(-3): "-3i", uint64(7): "7i", 0.5: "0.5", 1e21: "1e+21", "a\\b": `"a\\b"`} {
		if got, ok := influxValue(v); !ok || got != want {
			t.Errorf("influxValue(%v) = %q, want %q", v, got, want)
		}
	}
	for _, v := range []any{uint64(math.MaxUint64), math.Inf(1), math.NaN(), nil} {
		if _, ok := influxValue(v); ok {
			t.Errorf("influxValue(%v) must be left out", v)
		}
	}

	cfg = sinkConfig(t, `id: i, type: influxdb, url: "http://i", database: d, prefix: "snmp_", tags: [], keys: { exclude: [Octets] }`)
	enc = &influxEncoder{sink: &cfg}
	body, _ = enc.encode(nil, testBatch(t0))
	if s := string(body); !strings.HasPrefix(s, `snmp_system uptime=4200i,sysDescr=`) || strings.Contains(s, "Octets") || strings.Count(s, "\n") != 3 {
		// Without tags, both interfaces rows share a series: one line.
		t.Errorf("body:\n%s", s)
	}
}

// server is a fake destination recording what it accepts.
type server struct {
	*httptest.Server
	mu       sync.Mutex
	status   int // response status, 204 by default
	hang     chan struct{}
	requests []*http.Request
	bodies   [][]byte
	samples  atomic.Int64
	decode   func([]byte) int
}

func newServer(t *testing.T, decode func([]byte) int) *server {
	s := &server{status: http.StatusNoContent, decode: decode}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		status, hang := s.status, s.hang
		s.mu.Unlock()
		if hang != nil {
			select {
			case <-hang:
			case <-r.Context().Done():
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		if status/100 != 2 {
			http.Error(w, "server says no", status)
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, r)
		s.bodies = append(s.bodies, body)
		s.mu.Unlock()
		s.samples.Add(int64(s.decode(body)))
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) setStatus(code int) {
	s.mu.Lock()
	s.status = code
	s.mu.Unlock()
}

func influxCount(t *testing.T) func([]byte) int {
	return func(b []byte) int {
		n := 0
		for _, l := range decodeInflux(t, gunzip(t, b)) {
			n += len(l.fields)
		}
		return n
	}
}

func promCount(t *testing.T) func([]byte) int {
	return func(b []byte) int { return len(decodeProm(t, b)) }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// start builds, opens and starts a sink.
func start(t *testing.T, cfg config.Sink, dataDir string, log *slog.Logger) *Sink {
	t.Helper()
	s, err := New(cfg, dataDir, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	s.Start()
	return s
}

func TestSendInfluxDB(t *testing.T) {
	srv := newServer(t, influxCount(t))
	cfg := sinkConfig(t, `id: i, type: influxdb, url: "`+srv.URL+`/prefix/", database: "my db", token: s3cret, flush_interval: 20ms`)
	s := start(t, cfg, t.TempDir(), discard())
	defer s.Close()
	s.Write(testBatch(t0))
	waitFor(t, "the request", func() bool { return srv.samples.Load() == 7 })
	r := srv.requests[0]
	if r.URL.Path != "/prefix/api/v2/write" || r.URL.Query().Get("bucket") != "my db" || r.URL.Query().Get("precision") != "ms" {
		t.Errorf("url = %s", r.URL)
	}
	for k, v := range map[string]string{"Authorization": "Token s3cret", "Content-Encoding": "gzip", "User-Agent": UserAgent} {
		if r.Header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Header.Get(k), v)
		}
	}
	if st := s.Stats(); st.Sent != 7 || st.Requests != 1 || st.Dropped != 0 || st.BacklogSamples != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestSendPrometheus(t *testing.T) {
	srv := newServer(t, promCount(t))
	cfg := sinkConfig(t, `id: p, type: prometheus, url: "`+srv.URL+`/api/v1/write", username: u, password: pw,
		headers: { X-Scope-OrgID: tenant-1 }, batch_size: 12, flush_interval: 1h`)
	s := start(t, cfg, t.TempDir(), discard())
	defer s.Close()
	s.Write(testBatch(t0))
	time.Sleep(50 * time.Millisecond)
	if srv.samples.Load() != 0 {
		t.Fatal("sent before batch_size samples or flush_interval")
	}
	s.Write(testBatch(t0.Add(time.Minute))) // 12 samples: full batch
	waitFor(t, "the request", func() bool { return srv.samples.Load() == 12 })
	r := srv.requests[0]
	if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "pw" {
		t.Error("basic auth missing")
	}
	for k, v := range map[string]string{"Content-Encoding": "snappy", "Content-Type": "application/x-protobuf",
		"X-Prometheus-Remote-Write-Version": "0.1.0", "X-Scope-Orgid": "tenant-1"} {
		if r.Header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Header.Get(k), v)
		}
	}
}

// segments returns the disk buffer's segment files.
func segments(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	return m
}

// TestOutage: while the destination is down, data goes to the disk
// buffer; it is sent in order once the destination is back, and the
// buffer is emptied.
func TestOutage(t *testing.T) {
	srv := newServer(t, promCount(t))
	srv.setStatus(http.StatusServiceUnavailable)
	dataDir := t.TempDir()
	cfg := sinkConfig(t, `id: p, type: prometheus, url: "`+srv.URL+`", flush_interval: 5ms, tags: [device]`)
	s := start(t, cfg, dataDir, discard())
	defer s.Close()
	for i := range 20 {
		s.Write(testBatch(t0.Add(time.Duration(i) * time.Minute)))
		time.Sleep(10 * time.Millisecond)
	}
	waitFor(t, "the backlog on disk", func() bool { return s.Stats().BacklogSamples == 120 })
	dir := Dir(dataDir, "p")
	if len(segments(t, dir)) == 0 || s.Stats().BacklogBytes == 0 || !s.Stats().Down {
		t.Fatalf("nothing on disk: %v %+v", segments(t, dir), s.Stats())
	}
	srv.setStatus(http.StatusNoContent)
	waitFor(t, "the backlog to be sent", func() bool { return srv.samples.Load() == 120 })
	waitFor(t, "the buffer to be emptied", func() bool { return len(segments(t, dir)) == 0 })
	// In order: timestamps never go back.
	var last int64
	for _, b := range srv.bodies {
		for _, sr := range decodeProm(t, b) {
			if sr.labels["__name__"] == "snmp_uptime" {
				if sr.ts <= last {
					t.Fatalf("out of order: %d after %d", sr.ts, last)
				}
				last = sr.ts
			}
		}
	}
	if st := s.Stats(); st.Down || st.BacklogSamples != 0 || st.BacklogBytes != 0 {
		t.Errorf("stats = %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "cursor")); !os.IsNotExist(err) {
		t.Errorf("cursor left: %v", err)
	}
}

// TestRestart: what a stopped sink could not send is sent by the next run.
func TestRestart(t *testing.T) {
	srv := newServer(t, influxCount(t))
	srv.setStatus(http.StatusBadGateway)
	dataDir := t.TempDir()
	cfg := sinkConfig(t, `id: i, type: influxdb, url: "`+srv.URL+`", database: d, flush_interval: 5ms`)
	s := start(t, cfg, dataDir, discard())
	s.Write(testBatch(t0))
	waitFor(t, "the outage", func() bool { return s.Stats().Down })
	s.Write(testBatch(t0.Add(time.Minute))) // pending at Close: flushed to disk
	s.Close()
	if len(segments(t, Dir(dataDir, "i"))) == 0 {
		t.Fatal("nothing on disk after Close")
	}

	srv.setStatus(http.StatusNoContent)
	s = start(t, cfg, dataDir, discard())
	defer s.Close()
	waitFor(t, "the backlog of the previous run", func() bool { return srv.samples.Load() == 14 })
}

// TestDiskLimit: a full disk buffer drops its oldest data.
func TestDiskLimit(t *testing.T) {
	srv := newServer(t, promCount(t))
	srv.setStatus(http.StatusServiceUnavailable)
	dataDir := t.TempDir()
	cfg := sinkConfig(t, `id: p, type: prometheus, url: "`+srv.URL+`", flush_interval: 1ms, batch_size: 1, disk_buffer: 200KiB`)
	s := start(t, cfg, dataDir, discard())
	defer s.Close()
	waitFor(t, "the outage", func() bool { s.Write(testBatch(t0)); return s.Stats().Down })
	var dropped int64
	for i := range 3000 {
		s.Write(testBatch(t0.Add(time.Duration(i+1) * time.Second)))
	}
	waitFor(t, "drops", func() bool {
		st := s.Stats()
		dropped += st.Dropped
		return dropped > 0 && st.BacklogBytes <= 200<<10
	})
	if n := len(segments(t, Dir(dataDir, "p"))); n < 2 {
		t.Errorf("%d segments, want several", n)
	}
	srv.setStatus(http.StatusNoContent)
	waitFor(t, "the backlog", func() bool { return s.Stats().BacklogSamples == 0 })
	// The newest data is kept: the last batch was sent.
	last := t0.Add(3000 * time.Second).UnixMilli()
	found := false
	for _, b := range srv.bodies {
		for _, sr := range decodeProm(t, b) {
			found = found || sr.ts == last
		}
	}
	if !found {
		t.Error("the newest batch was dropped")
	}
}

// TestNoDiskBuffer: with disk_buffer 0, nothing is written to disk: data
// waits in memory, and is lost at Close.
func TestNoDiskBuffer(t *testing.T) {
	srv := newServer(t, influxCount(t))
	srv.setStatus(http.StatusServiceUnavailable)
	dataDir := t.TempDir()
	cfg := sinkConfig(t, `id: i, type: influxdb, url: "`+srv.URL+`", database: d, flush_interval: 5ms, disk_buffer: 0, timeout: 50ms`)
	s := start(t, cfg, dataDir, discard())
	s.Write(testBatch(t0))
	waitFor(t, "the outage", func() bool { return s.Stats().Down })
	s.Write(testBatch(t0.Add(time.Minute)))
	waitFor(t, "the backlog", func() bool { return s.Stats().BacklogSamples == 14 })
	srv.setStatus(http.StatusNoContent)
	waitFor(t, "the backlog to be sent from memory", func() bool { return srv.samples.Load() == 14 })

	srv.setStatus(http.StatusServiceUnavailable)
	s.Write(testBatch(t0.Add(2 * time.Minute)))
	waitFor(t, "the outage", func() bool { return s.Stats().Down })
	s.Close()
	if st := s.Stats(); st.Dropped != 7 {
		t.Errorf("dropped = %d, want 7", st.Dropped)
	}
	if _, err := os.Stat(filepath.Join(dataDir, config.SinksDir)); !os.IsNotExist(err) {
		t.Errorf("sinks dir created: %v", err)
	}
}

// TestRejected: a request the destination refuses for good (400) is
// dropped, not retried forever.
func TestRejected(t *testing.T) {
	srv := newServer(t, promCount(t))
	srv.setStatus(http.StatusBadRequest)
	cfg := sinkConfig(t, `id: p, type: prometheus, url: "`+srv.URL+`", flush_interval: 5ms`)
	s := start(t, cfg, t.TempDir(), discard())
	defer s.Close()
	s.Write(testBatch(t0))
	var st Stats
	waitFor(t, "the drop", func() bool { st = s.Stats(); return st.Dropped == 6 })
	if st.Down || st.BacklogSamples != 0 {
		t.Errorf("stats = %+v", st)
	}
	srv.setStatus(http.StatusNoContent)
	s.Write(testBatch(t0.Add(time.Minute)))
	waitFor(t, "the next batch", func() bool { return srv.samples.Load() == 6 })
}

// TestNonBlocking: a destination that hangs delays neither Write nor the
// other sinks.
func TestNonBlocking(t *testing.T) {
	stuck := newServer(t, promCount(t))
	stuck.hang = make(chan struct{})
	defer close(stuck.hang)
	ok := newServer(t, promCount(t))
	dataDir := t.TempDir()
	a := start(t, sinkConfig(t, `id: a, type: prometheus, url: "`+stuck.URL+`", flush_interval: 1ms, timeout: 30s`), dataDir, discard())
	b := start(t, sinkConfig(t, `id: b, type: prometheus, url: "`+ok.URL+`", flush_interval: 1ms`), dataDir, discard())
	defer b.Close()
	begin := time.Now()
	for i := range 200 {
		batch := testBatch(t0.Add(time.Duration(i) * time.Second))
		a.Write(batch)
		b.Write(batch)
	}
	if d := time.Since(begin); d > time.Second {
		t.Errorf("200 writes took %v", d)
	}
	waitFor(t, "the healthy sink", func() bool { return ok.samples.Load() == 1200 })
	go a.Close() // returns once its timeout expires
}

// TestTornSegment: a record cut short by a crash is removed on open; the
// records before it are kept.
func TestTornSegment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "q")
	q, _, err := acquire(dir, true, discard())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		q.append(record{seq: uint64(i + 1), kind: kindInfluxDB, samples: 10, data: bytes.Repeat([]byte{byte(i)}, 100)}, 1<<20)
	}
	q.release(nil)
	path := segments(t, dir)[0]
	st, _ := os.Stat(path)
	if err := os.Truncate(path, st.Size()-50); err != nil {
		t.Fatal(err)
	}
	// And a corrupt payload in the second record.
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	f.WriteAt([]byte{0xff}, headerSize+100+headerSize+10)
	f.Close()

	var logs bytes.Buffer
	q, _, err = acquire(dir, false, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil || q == nil {
		t.Fatal(err)
	}
	defer q.release(nil)
	if q.backlog() != 20 {
		t.Errorf("backlog = %d, want 20", q.backlog())
	}
	r, ok := q.peek()
	if !ok || r.seq != 1 || !bytes.Equal(r.data, bytes.Repeat([]byte{0}, 100)) {
		t.Fatalf("first record = %+v %v", r.seq, ok)
	}
	q.pop(1)
	if r, ok := q.peek(); ok {
		t.Errorf("corrupt record returned: %d", r.seq)
	}
	if !strings.Contains(logs.String(), "incomplete record") || !strings.Contains(logs.String(), "checksum mismatch") {
		t.Errorf("logs:\n%s", logs.String())
	}
	if q.backlog() != 0 || len(segments(t, dir)) != 0 {
		t.Errorf("backlog %d, segments %v", q.backlog(), segments(t, dir))
	}
}

// TestCursor: records read before a restart are not read again.
func TestCursor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "q")
	q, _, _ := acquire(dir, true, discard())
	q.setLimit(1 << 20)
	for i := range 5 {
		q.append(record{seq: uint64(i + 1), samples: 1, data: make([]byte, 40<<10)}, 1<<20)
	}
	if n := len(segments(t, dir)); n != 2 { // 128KiB segments: 4 records, then 1
		t.Errorf("%d segments", n)
	}
	for i := range 3 {
		r, _ := q.peek()
		if !q.pop(r.seq) || r.seq != uint64(i+1) {
			t.Fatalf("pop %d", r.seq)
		}
	}
	if q.pop(1) {
		t.Error("popped a record that is not the head")
	}
	q.release(nil)
	q, _, _ = acquire(dir, false, discard())
	defer q.release(nil)
	if r, ok := q.peek(); !ok || r.seq != 4 || q.backlog() != 2 {
		t.Errorf("after restart: head %d, backlog %d", r.seq, q.backlog())
	}
}

// TestReplacedSink: a sink replaced by a reload shares the disk buffer
// with its successor, which alone reads it.
func TestReplacedSink(t *testing.T) {
	srv := newServer(t, promCount(t))
	srv.setStatus(http.StatusServiceUnavailable)
	dataDir := t.TempDir()
	cfg := sinkConfig(t, `id: p, type: prometheus, url: "`+srv.URL+`", flush_interval: 5ms`)
	old := start(t, cfg, dataDir, discard())
	old.Write(testBatch(t0))
	waitFor(t, "the outage", func() bool { return old.Stats().Down })

	cfg.Tags = nil
	next := start(t, cfg, dataDir, discard())
	defer next.Close()
	old.Write(testBatch(t0.Add(time.Minute))) // a poll still running at the reload
	old.Close()
	srv.setStatus(http.StatusNoContent)
	waitFor(t, "both batches", func() bool { return srv.samples.Load() == 12 })
	time.Sleep(50 * time.Millisecond)
	if n := srv.samples.Load(); n != 12 {
		t.Errorf("%d samples sent, want 12 (duplicates?)", n)
	}
}

// TestOtherTypeBacklog: records written by a sink of another type are
// dropped, not sent.
func TestOtherTypeBacklog(t *testing.T) {
	dataDir := t.TempDir()
	q, _, _ := acquire(Dir(dataDir, "x"), true, discard())
	q.append(record{seq: 1, kind: kindInfluxDB, samples: 3, data: []byte("cpu v=1 1")}, 1<<20)
	q.release(nil)
	srv := newServer(t, promCount(t))
	s := start(t, sinkConfig(t, `id: x, type: prometheus, url: "`+srv.URL+`"`), dataDir, discard())
	defer s.Close()
	waitFor(t, "the drop", func() bool { return s.Stats().Dropped == 3 })
	if srv.samples.Load() != 0 {
		t.Error("influx data sent to prometheus")
	}
}

func TestUvarintLen(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 16383, 16384, 1 << 30} {
		if uvarintLen(n) != len(binary.AppendUvarint(nil, uint64(n))) {
			t.Errorf("uvarintLen(%d)", n)
		}
	}
}
