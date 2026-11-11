package sink

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/airtg-io/schema"
	airtgv1 "github.com/airtg-io/schema/airtg/v1"
	"github.com/airtg-io/schema/fixtures"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// freePort returns a TCP port free on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// analyzer is a JetStream server standing for the analyzer's.
type analyzer struct {
	srv *natsserver.Server
	nc  *nats.Conn
	js  jetstream.JetStream
}

// startAnalyzer starts a JetStream server on port, with the stream of
// every AIrtg subject unless noStream, and points AnalyzerURL at it.
func startAnalyzer(t *testing.T, port int, noStream bool, opts ...func(*natsserver.Options)) *analyzer {
	t.Helper()
	o := &natsserver.Options{Host: "127.0.0.1", Port: port, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true}
	for _, f := range opts {
		f(o)
	}
	srv, err := natsserver.NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	a := &analyzer{srv: srv, nc: nc, js: js}
	if !noStream {
		a.createStream(t)
	}
	setAnalyzerURL(t, srv.ClientURL())
	return a
}

func setAnalyzerURL(t *testing.T, url string) {
	prev := AnalyzerURL
	AnalyzerURL = url
	t.Cleanup(func() { AnalyzerURL = prev })
}

func (a *analyzer) createStream(t *testing.T) {
	t.Helper()
	_, err := a.js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name: "AIRTG", Subjects: []string{schema.SubjectAll}, Duplicates: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// received is one message stored by the analyzer.
type received struct {
	subject, msgID string
	env            *airtgv1.Envelope
}

// messages returns every message of the stream, decoded.
func (a *analyzer) messages(t *testing.T) []received {
	t.Helper()
	ctx := context.Background()
	st, err := a.js.Stream(ctx, "AIRTG")
	if err != nil {
		t.Fatal(err)
	}
	info, err := st.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out []received
	for seq := info.State.FirstSeq; seq <= info.State.LastSeq && info.State.Msgs > 0; seq++ {
		m, err := st.GetMsg(ctx, seq)
		if err != nil {
			t.Fatal(err)
		}
		env := &airtgv1.Envelope{}
		if err := proto.Unmarshal(m.Data, env); err != nil {
			t.Fatalf("message %d: %v", seq, err)
		}
		out = append(out, received{subject: m.Subject, msgID: m.Header.Get(jetstream.MsgIDHeader), env: env})
	}
	return out
}

func (a *analyzer) count(t *testing.T) int {
	t.Helper()
	st, err := a.js.Stream(context.Background(), "AIRTG")
	if err != nil {
		return 0
	}
	info, err := st.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return int(info.State.Msgs)
}

func airtgConfig(t *testing.T) config.Sink { return sinkConfig(t, "id: analyzer, type: airtg") }

// airtgBatch is testBatch with what airtg sends besides samples.
func airtgBatch(at, discovered time.Time) *Batch {
	b := testBatch(at)
	b.Interval = time.Minute
	b.DiscoveredAt = discovered
	b.Capabilities = []string{"system", "interfaces", "storage"}
	return b
}

func TestAirtgSend(t *testing.T) {
	a := startAnalyzer(t, -1, false)
	s := start(t, airtgConfig(t), t.TempDir(), discard())
	defer s.Close()

	s.Write(airtgBatch(t0, t0))
	waitFor(t, "inventory and metrics", func() bool { return a.count(t) == 2 })
	msgs := a.messages(t)
	host, _ := os.Hostname()
	for _, m := range msgs {
		e := m.env
		if m.msgID != e.GetId() || len(e.GetId()) != 36 {
			t.Errorf("Nats-Msg-Id %q, envelope id %q", m.msgID, e.GetId())
		}
		if e.GetSchemaVersion() != schema.Version || e.GetTime() == nil || e.GetTenantId() != "" {
			t.Errorf("envelope header = %v", e)
		}
		p := e.GetProducer()
		if p.GetType() != "snmp-poller" || p.GetVersion() != Version || p.GetHostname() != host || p.GetId() != "" {
			t.Errorf("producer = %v", p)
		}
	}

	inv := msgs[0].env.GetInventory()
	if msgs[0].subject != "airtg.v1.inventory.r1" || inv == nil {
		t.Fatalf("first message: %s %v", msgs[0].subject, msgs[0].env)
	}
	if inv.GetDevice().GetId() != "r1" || inv.GetDevice().GetAddress() != "192.0.2.1" ||
		!inv.GetDiscoveredAt().AsTime().Equal(t0) ||
		strings.Join(inv.GetCapabilities(), ",") != "interfaces,storage,system" ||
		inv.GetScalars()["sysLocation"] != "Paris\nrack 4" ||
		inv.GetColumns()["ifDescr"].GetRows()["2"] != "eth 1" || len(inv.GetColumns()) != 3 {
		t.Errorf("inventory = %v", inv)
	}

	mb := msgs[1].env.GetMetrics()
	if msgs[1].subject != "airtg.v1.metrics.r1" || mb == nil {
		t.Fatalf("second message: %s %v", msgs[1].subject, msgs[1].env)
	}
	if mb.GetDevice().GetId() != "r1" || mb.GetInterval().AsDuration() != time.Minute || len(mb.GetSamples()) != 8 {
		t.Fatalf("metrics = %v", mb)
	}
	// Every sample, every value type and mode, as polled.
	var got []string
	for _, smp := range mb.GetSamples() {
		got = append(got, fmt.Sprintf("%s/%s/%s/%s %v %s %s %v %v %s", smp.GetCapability(), smp.GetTable(), smp.GetIndex(),
			smp.GetMetric(), smp.GetMode(), smp.GetSourceType(), smp.GetUnit(), smp.GetValue(), smp.GetLabels(),
			smp.GetTime().AsTime().Format("15:04:05.000")))
	}
	want := []string{
		"system///uptime MODE_RAW   &{4200} map[] 10:00:00.000",
		`system///sysDescr MODE_RAW   &{Linux "x"` + "\n" + `2.6} map[] 10:00:00.000`,
		"interfaces/interfaces/1/ifInOctets MODE_RATE   &{1250.5} map[ifAlias:uplink, to core ifDescr:eth0] 10:00:00.000",
		"interfaces/interfaces/1/ifInOctets MODE_VOLUME   &{75030} map[ifAlias:uplink, to core ifDescr:eth0] 10:00:00.000",
		"interfaces/interfaces/1/ifOperStatus MODE_RAW   &{1} map[ifAlias:uplink, to core ifDescr:eth0] 10:00:00.003",
		"interfaces/interfaces/2/ifOperStatus MODE_RAW   &{2} map[ifDescr:eth 1] 10:00:00.000",
		"interfaces/interfaces/2/ifInOctets MODE_RATE   &{NaN} map[ifDescr:eth 1] 10:00:00.000",
		`storage/storage/1/storageUsed MODE_RAW Formula  &{1099511627776} map[hrStorageDescr:C:\ Label="sys"] 10:00:00.000`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("samples:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The same discovery: metrics only. A new one: its inventory first.
	s.Write(airtgBatch(t0.Add(time.Minute), t0))
	waitFor(t, "metrics only", func() bool { return a.count(t) == 3 })
	s.Write(airtgBatch(t0.Add(2*time.Minute), t0.Add(time.Hour)))
	waitFor(t, "new inventory", func() bool { return a.count(t) == 5 })
	msgs = a.messages(t)
	if msgs[2].env.GetMetrics() == nil || msgs[3].env.GetInventory() == nil || msgs[4].env.GetMetrics() == nil {
		t.Errorf("payloads = %T %T %T", msgs[2].env.GetPayload(), msgs[3].env.GetPayload(), msgs[4].env.GetPayload())
	}
	if st := s.Stats(); st.Sent != 24 || st.Dropped != 0 || st.Down {
		t.Errorf("stats = %+v", st)
	}
}

// The analyzer starts after the poller: data waits in the disk buffer and
// arrives once, in order.
func TestAirtgOutage(t *testing.T) {
	port := freePort(t)
	setAnalyzerURL(t, fmt.Sprintf("nats://127.0.0.1:%d", port))
	s := start(t, airtgConfig(t), t.TempDir(), discard())
	defer s.Close()
	s.Write(airtgBatch(t0, t0))
	waitFor(t, "destination down", func() bool { return s.Stats().Down })
	s.Write(airtgBatch(t0.Add(time.Minute), t0))

	a := startAnalyzer(t, port, false)
	waitFor(t, "backlog delivered", func() bool { return a.count(t) == 3 })
	time.Sleep(100 * time.Millisecond) // no duplicate follows
	msgs := a.messages(t)
	if len(msgs) != 3 || msgs[0].env.GetInventory() == nil ||
		!msgs[2].env.GetMetrics().GetSamples()[0].GetTime().AsTime().Equal(t0.Add(time.Minute)) {
		t.Errorf("messages = %d %v", len(msgs), msgs)
	}
	waitFor(t, "destination up", func() bool { return !s.Stats().Down })
}

// Without the analyzer, the error says so plainly.
func TestAirtgNotConnected(t *testing.T) {
	port := freePort(t)
	c := &natsClient{url: fmt.Sprintf("nats://127.0.0.1:%d", port), timeout: time.Second}
	defer c.close()
	payload, _, _ := newAirtgEncoder().encode(nil, airtgBatch(t0, t0), nil)
	err := c.post(context.Background(), payload)
	if err == nil || !strings.HasPrefix(err.Error(), "not connected to the analyzer") {
		t.Errorf("err = %v", err)
	}
}

// The analyzer runs but has not created its stream yet: retried until it
// does.
func TestAirtgNoStream(t *testing.T) {
	a := startAnalyzer(t, -1, true)
	s := start(t, airtgConfig(t), t.TempDir(), discard())
	defer s.Close()
	s.Write(airtgBatch(t0, t0))
	waitFor(t, "failures", func() bool { return s.Stats().Failures > 0 })
	a.createStream(t)
	waitFor(t, "delivered", func() bool { return a.count(t) == 2 })
}

// A payload published twice (a retry after a lost acknowledgement) is
// stored once.
func TestAirtgDuplicate(t *testing.T) {
	a := startAnalyzer(t, -1, false)
	c := &natsClient{url: AnalyzerURL, timeout: 5 * time.Second}
	defer c.close()
	enc := newAirtgEncoder()
	payload, _, _ := enc.encode(nil, airtgBatch(t0, t0), nil)
	for range 2 {
		if err := c.post(context.Background(), payload); err != nil {
			t.Fatal(err)
		}
	}
	if n := a.count(t); n != 2 {
		t.Errorf("stored %d messages, want 2", n)
	}
}

// A message larger than the server accepts is dropped, not retried forever.
func TestAirtgTooLarge(t *testing.T) {
	startAnalyzer(t, -1, false, func(o *natsserver.Options) { o.MaxPayload = 1024 })
	c := &natsClient{url: AnalyzerURL, timeout: 5 * time.Second}
	defer c.close()
	b := airtgBatch(t0, t0)
	b.Discovery["sysDescr"] = strings.Repeat("x", 4096)
	payload, _, _ := newAirtgEncoder().encode(nil, b, nil)
	var perm *permanentError
	if err := c.post(context.Background(), payload); !errors.As(err, &perm) {
		t.Errorf("err = %v, want a permanent error", err)
	}
}

// New, used by -check, never connects.
func TestAirtgNoConnectOnNew(t *testing.T) {
	setAnalyzerURL(t, "nats://192.0.2.1:4222") // unroutable: a connection would hang
	s, err := New(airtgConfig(t), t.TempDir(), discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// decodeFrames decodes an encoder output.
func decodeFrames(t *testing.T, buf []byte) []*airtgv1.Envelope {
	t.Helper()
	frames, err := readFrames(buf)
	if err != nil {
		t.Fatal(err)
	}
	var envs []*airtgv1.Envelope
	for _, f := range frames {
		env := &airtgv1.Envelope{}
		if err := proto.Unmarshal(f.data, env); err != nil {
			t.Fatal(err)
		}
		if f.id != env.GetId() {
			t.Errorf("frame id %q, envelope id %q", f.id, env.GetId())
		}
		envs = append(envs, env)
	}
	return envs
}

// A large poll is split into batches that each fit a message.
func TestAirtgSplit(t *testing.T) {
	b := airtgBatch(t0, time.Time{}) // no discovery time: no inventory
	b.Samples = nil
	for i := range 30000 {
		b.Samples = append(b.Samples, Sample{
			Capability: "interfaces", Table: "interfaces", Index: fmt.Sprint(i), Metric: "ifInOctets",
			Labels: map[string]string{"ifDescr": fmt.Sprintf("GigabitEthernet1/0/%d", i), "ifAlias": strings.Repeat("a", 40)},
			Mode:   config.ModeRate, Unit: "bytes/s", Value: float64(i), Time: t0,
		})
	}
	buf, units, n := newAirtgEncoder().encode(nil, b, nil)
	frames, err := readFrames(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 30000 || len(units) != len(frames) || len(frames) < 3 {
		t.Fatalf("n = %d, units = %d, frames = %d", n, len(units), len(frames))
	}
	total, start := 0, 0
	for i, env := range decodeFrames(t, buf) {
		if size := len(frames[i].data); size > 1<<20-4096 {
			t.Errorf("message %d: %d bytes", i, size)
		}
		total += len(env.GetMetrics().GetSamples())
		if units[i].samples != len(env.GetMetrics().GetSamples()) {
			t.Errorf("unit %d: %d samples, message has %d", i, units[i].samples, len(env.GetMetrics().GetSamples()))
		}
		// Each unit ends where its frame does: requests may be cut there.
		if _, err := readFrames(buf[start:units[i].end]); err != nil {
			t.Errorf("unit %d: %v", i, err)
		}
		start = units[i].end
	}
	if total != 30000 {
		t.Errorf("samples = %d", total)
	}
}

// Device strings may hold anything: they are sent as valid UTF-8.
func TestAirtgInvalidUTF8(t *testing.T) {
	b := airtgBatch(t0, t0)
	b.Discovery["sysName"] = "r1\xff"
	b.Columns["ifDescr"]["1"] = "\xfeeth0"
	b.Samples = []Sample{{Capability: "system", Metric: "x\xff", Mode: config.ModeRaw,
		Labels: map[string]string{"l\xff": "v\xff"}, Value: "a\xffb", Time: t0}}
	buf, _, _ := newAirtgEncoder().encode(nil, b, nil)
	envs := decodeFrames(t, buf)
	smp := envs[1].GetMetrics().GetSamples()[0]
	if envs[0].GetInventory().GetScalars()["sysName"] != "r1\uFFFD" ||
		envs[0].GetInventory().GetColumns()["ifDescr"].GetRows()["1"] != "\uFFFDeth0" ||
		smp.GetStringValue() != "a\uFFFDb" || smp.GetMetric() != "x\uFFFD" || smp.GetLabels()["l\uFFFD"] != "v\uFFFD" {
		t.Errorf("envelopes = %v", envs)
	}
}

// The poller sends what the schema's fixtures show: for the same polled
// data, the same messages (but for the per-message id, time and producer).
func TestAirtgFixtures(t *testing.T) {
	ft0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sec := ft0.Add(time.Second)
	if1 := map[string]string{"ifDescr": "GigabitEthernet0/1", "ifName": "Gi0/1"}
	mem := map[string]string{"hrStorageDescr": "Physical memory"}
	b := &Batch{
		DeviceID: "core-sw1", Address: "192.0.2.10", Interval: time.Minute, DiscoveredAt: ft0,
		Capabilities: []string{"system", "interfaces", "entity", "host-resources"},
		Discovery: map[string]string{
			"sysName": "core-sw1.example.net", "sysDescr": "Cisco IOS XE Software, Version 17.09.04",
			"sysObjectID": ".1.3.6.1.4.1.9.1.2494", "sysLocation": "DC1, row 4, rack 12", "sysContact": "noc@example.net",
		},
		Columns: map[string]map[string]string{
			"ifDescr": {"1": "GigabitEthernet0/1", "2": "GigabitEthernet0/2"},
			"ifName":  {"1": "Gi0/1", "2": "Gi0/2"},
			"ifAlias": {"1": "uplink to core-sw2", "2": ""},
		},
		Samples: []Sample{
			{Capability: "system", Metric: "sysUpTime", Mode: config.ModeRaw, Type: "TimeTicks", Value: uint64(864000000), Time: ft0},
			{Capability: "interfaces", Metric: "ifHCInOctets", Table: "ifTable", Index: "1", Labels: if1, Mode: config.ModeRaw,
				Type: "Counter64", Unit: "bytes", Value: uint64(18446744073709551000), Time: sec},
			{Capability: "interfaces", Metric: "ifHCInOctets", Table: "ifTable", Index: "1", Labels: if1, Mode: config.ModeRate,
				Type: "Counter64", Unit: "bytes/s", Value: 1250000.5, Time: sec},
			{Capability: "interfaces", Metric: "ifHCInOctets", Table: "ifTable", Index: "1", Labels: if1, Mode: config.ModeVolume,
				Type: "Counter64", Unit: "bytes", Value: 75000030.0, Time: sec},
			{Capability: "host-resources", Metric: "hrStorageSizeBytes", Table: "hrStorageTable", Index: "1", Labels: mem,
				Mode: config.ModeRaw, Type: TypeFormula, Unit: "bytes", Value: int64(17179869184), Time: sec},
			{Capability: "host-resources", Metric: "hrStorageUsedPercent", Table: "hrStorageTable", Index: "1", Labels: mem,
				Mode: config.ModeRaw, Type: TypeFormula, Unit: "percent", Value: 42.5, Time: sec},
			{Capability: "entity", Metric: "entPhysicalSoftwareRev", Table: "entPhysicalTable", Index: "1",
				Labels: map[string]string{"entPhysicalName": "Chassis"}, Mode: config.ModeRaw, Type: "OctetString",
				Value: "17.9.4", Time: sec},
		},
	}
	buf, _, _ := newAirtgEncoder().encode(nil, b, nil)
	got := decodeFrames(t, buf)
	if len(got) != 2 {
		t.Fatalf("%d envelopes", len(got))
	}
	for i, name := range []string{"inventory", "metrics"} {
		data, err := fs.ReadFile(fixtures.FS, "v1/"+name+".binpb")
		if err != nil {
			t.Fatal(err)
		}
		want := &airtgv1.Envelope{}
		if err := proto.Unmarshal(data, want); err != nil {
			t.Fatal(err)
		}
		for _, e := range []*airtgv1.Envelope{want, got[i]} {
			e.Id, e.Time, e.Producer, e.SchemaVersion = "", nil, nil, ""
		}
		if !proto.Equal(got[i], want) {
			t.Errorf("%s:\n got %v\nwant %v", name, got[i], want)
		}
	}
}
