package poller

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/state"
	"github.com/airtg-io/snmp-poller/internal/testagent"
)

// capture is an output that records batches, for tests.
type capture struct {
	mu      sync.Mutex
	batches []*output.Batch
}

func (c *capture) Write(_ context.Context, b *output.Batch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, b)
	return nil
}
func (c *capture) Close() error { return nil }

func (c *capture) count(dev string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, b := range c.batches {
		if b.DeviceID == dev {
			n++
		}
	}
	return n
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func sysMIB(name string) map[string]testagent.Value {
	return map[string]testagent.Value{
		"1.3.6.1.2.1.1.1.0": {Type: gosnmp.OctetString, Value: "Test agent " + name},
		"1.3.6.1.2.1.1.2.0": {Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.4.1.99999"},
		"1.3.6.1.2.1.1.3.0": {Type: gosnmp.TimeTicks, Value: uint32(1000)},
		"1.3.6.1.2.1.1.5.0": {Type: gosnmp.OctetString, Value: name},
	}
}

func ifMIB() *testagent.MIB {
	vals := sysMIB("router")
	for i, name := range []string{"eth0", "eth1", "lo"} {
		idx := i + 1
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.1.%d", idx)] = testagent.Value{Type: gosnmp.OctetString, Value: name}
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.18.%d", idx)] = testagent.Value{Type: gosnmp.OctetString, Value: "alias-" + name}
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.6.%d", idx)] = testagent.Value{Type: gosnmp.Counter64, Value: uint64(1_000_000)}
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.10.%d", idx)] = testagent.Value{Type: gosnmp.Counter32, Value: uint32(math.MaxUint32 - 499)}
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.8.%d", idx)] = testagent.Value{Type: gosnmp.Integer, Value: 1}
	}
	// Unlabelled table: rows 1.1 and 2.1.
	vals["1.3.6.1.2.1.25.2.3.1.6.1.1"] = testagent.Value{Type: gosnmp.Integer, Value: 10}
	vals["1.3.6.1.2.1.25.2.3.1.6.2.1"] = testagent.Value{Type: gosnmp.Integer, Value: 20}
	return testagent.NewMIB(vals)
}

func newDevice(t *testing.T, doc string, out output.Output) (*device, *state.Store) {
	t.Helper()
	cfg, err := config.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &device{
		spec:    cfg.DeviceSpecs()[0],
		log:     slog.New(slog.DiscardHandler),
		outputs: []output.Output{out},
	}, store
}

func find(b *output.Batch, metric, idx string, mode config.Mode) (output.Sample, bool) {
	for _, s := range b.Samples {
		if s.Metric == metric && s.Index == idx && s.Mode == mode {
			return s, true
		}
	}
	return output.Sample{}, false
}

var (
	auths = map[string]gosnmp.SnmpV3AuthProtocol{
		"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224,
		"SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
	}
	privs = map[string]gosnmp.SnmpV3PrivProtocol{
		"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192,
		"AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C,
	}
)

// TestVersionsAndSecurity polls a real agent over every SNMP version,
// v3 security level and auth/priv protocol combination.
func TestVersionsAndSecurity(t *testing.T) {
	users := []testagent.User{{Name: "noauth"}}
	cases := map[string]string{
		"v1":              `version: 1, community: ` + testagent.Community,
		"v2c":             `version: 2c, community: ` + testagent.Community,
		"v3-noAuthNoPriv": `version: 3, username: noauth`,
	}
	for an, ap := range auths {
		users = append(users, testagent.User{Name: "a-" + an, Auth: ap})
		cases["v3-authNoPriv-"+an] = fmt.Sprintf(`version: 3, username: a-%s, auth_protocol: %s, auth_passphrase: %s`,
			an, an, testagent.AuthPass)
		for pn, pp := range privs {
			u := "ap-" + an + "-" + pn
			users = append(users, testagent.User{Name: u, Auth: ap, Priv: pp})
			cases["v3-authPriv-"+an+"-"+pn] = fmt.Sprintf(
				`version: 3, username: %s, auth_protocol: %s, auth_passphrase: %s, priv_protocol: %s, priv_passphrase: %s`,
				u, an, testagent.AuthPass, pn, testagent.PrivPass)
		}
	}
	agent := testagent.Start(t, users, testagent.NewMIB(sysMIB("default")),
		map[string]*testagent.MIB{"ctx1": testagent.NewMIB(sysMIB("in-ctx1"))})
	cases["v3-context"] = fmt.Sprintf(`version: 3, username: ap-SHA256-AES, auth_protocol: SHA256, auth_passphrase: %s, priv_protocol: AES, priv_passphrase: %s, context_name: ctx1`,
		testagent.AuthPass, testagent.PrivPass)

	for name, snmpCfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := &capture{}
			d, store := newDevice(t, fmt.Sprintf(`
devices:
  - id: dev
    address: 127.0.0.1
    port: %d
    timeout: 2s
    snmp: { %s }
    scalars: [{ name: sysUpTime, oid: 1.3.6.1.2.1.1.3.0 }]
`, agent.Port, snmpCfg), out)
			if _, err := d.poll(context.Background(), store, time.Now); err != nil {
				t.Fatalf("poll: %v", err)
			}
			b := out.batches[0]
			want := "default"
			if name == "v3-context" {
				want = "in-ctx1"
			}
			if b.Discovery["sysName"] != want {
				t.Errorf("sysName = %q, want %q", b.Discovery["sysName"], want)
			}
			s, ok := find(b, "sysUpTime", "", config.ModeRaw)
			if !ok || s.Value != uint64(1000) || s.Type != "TimeTicks" {
				t.Errorf("sysUpTime sample = %+v, %v", s, ok)
			}
		})
	}
}

func TestWrongCredentialsFail(t *testing.T) {
	agent := testagent.Start(t, []testagent.User{{Name: "u", Auth: gosnmp.SHA, Priv: gosnmp.AES}},
		testagent.NewMIB(sysMIB("x")), nil)
	for name, snmpCfg := range map[string]string{
		"community":  `version: 2c, community: wrong`,
		"passphrase": `version: 3, username: u, auth_protocol: SHA, auth_passphrase: wrong-pass, priv_protocol: AES, priv_passphrase: ` + testagent.PrivPass,
	} {
		t.Run(name, func(t *testing.T) {
			d, store := newDevice(t, fmt.Sprintf(`
devices:
  - { id: dev, address: 127.0.0.1, port: %d, timeout: 300ms, retries: 0, snmp: { %s }, scalars: [{ name: a, oid: 1.3.6.1.2.1.1.3.0 }] }
`, agent.Port, snmpCfg), &capture{})
			res, err := d.poll(context.Background(), store, time.Now)
			if err == nil || !res.discoveryErr {
				t.Fatalf("expected discovery failure, got res=%+v err=%v", res, err)
			}
			if strings.Contains(err.Error(), "wrong") {
				t.Errorf("error leaks credential: %v", err)
			}
		})
	}
}

// TestRatesTablesAndRediscovery covers row selection, labels, raw/rate/volume,
// Counter32 wrap, on-disk state and state reset on rediscovery.
func TestRatesTablesAndRediscovery(t *testing.T) {
	mib := ifMIB()
	agent := testagent.Start(t, nil, mib, nil)
	out := &capture{}
	d, store := newDevice(t, fmt.Sprintf(`
devices:
  - id: router
    address: 127.0.0.1
    port: %d
    discovery_interval: 1h
    snmp: { version: 2c, community: %s }
    discovery:
      columns:
        ifName: 1.3.6.1.2.1.31.1.1.1.1
        ifAlias: 1.3.6.1.2.1.31.1.1.1.18
    scalars:
      - { name: sysUpTime, oid: 1.3.6.1.2.1.1.3.0, modes: [raw, rate] }
      - { name: absent, oid: 1.3.6.1.2.1.1.77.0 }
    tables:
      - name: if
        label: ifName
        labels: [ifAlias]
        include: ["^eth"]
        columns:
          - { name: hcIn, oid: 1.3.6.1.2.1.31.1.1.1.6, modes: [raw, rate, volume] }
          - { name: in32, oid: 1.3.6.1.2.1.2.2.1.10, modes: [volume] }
          - { name: oper, oid: 1.3.6.1.2.1.2.2.1.8 }
      - name: storage
        include: ["^2\\."]
        columns:
          - { name: used, oid: 1.3.6.1.2.1.25.2.3.1.6 }
`, agent.Port, testagent.Community), out)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}

	// Poll 1: discovery + raw values only.
	res, err := d.poll(context.Background(), store, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.discovered || res.missing != 1 {
		t.Errorf("poll 1: %+v", res)
	}
	b := out.batches[0]
	if got := fmt.Sprint(d.discovery.Rows["if"]); got != "[1 2]" {
		t.Errorf("selected rows = %s, want [1 2] (lo excluded)", got)
	}
	if _, ok := find(b, "hcIn", "3", config.ModeRaw); ok {
		t.Error("lo must not be polled")
	}
	s, ok := find(b, "hcIn", "2", config.ModeRaw)
	if !ok || s.Value != uint64(1_000_000) || s.Labels["ifName"] != "eth1" || s.Labels["ifAlias"] != "alias-eth1" || s.Table != "if" {
		t.Errorf("hcIn.2 = %+v", s)
	}
	if _, ok := find(b, "hcIn", "1", config.ModeRate); ok {
		t.Error("first poll must not produce rates")
	}
	if _, ok := find(b, "used", "2.1", config.ModeRaw); !ok {
		t.Error("unlabelled table row 2.1 missing")
	}
	if _, ok := find(b, "used", "1.1", config.ModeRaw); ok {
		t.Error("unlabelled table row 1.1 must be filtered by include")
	}
	if _, err := os.Stat(filepath.Join(store.DeviceDir("router"), "state.json")); err != nil {
		t.Errorf("state file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.DeviceDir("router"), "discovery.json")); err != nil {
		t.Errorf("discovery file not written: %v", err)
	}

	// Poll 2: 10s later, counters moved (Counter32 wraps).
	clk.advance(10 * time.Second)
	mib.Set("1.3.6.1.2.1.31.1.1.1.6.1", uint64(1_050_000))
	mib.Set("1.3.6.1.2.1.2.2.1.10.1", uint32(500))
	mib.Set("1.3.6.1.2.1.1.3.0", uint32(2000))
	res, err = d.poll(context.Background(), store, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if res.discovered {
		t.Error("poll 2 must not rediscover")
	}
	b = out.batches[1]
	if s, _ := find(b, "hcIn", "1", config.ModeRate); s.Value != 5000.0 {
		t.Errorf("hcIn rate = %v, want 5000", s.Value)
	}
	if s, _ := find(b, "hcIn", "1", config.ModeVolume); s.Value != 50000.0 {
		t.Errorf("hcIn volume = %v, want 50000", s.Value)
	}
	if s, _ := find(b, "in32", "1", config.ModeVolume); s.Value != 1000.0 {
		t.Errorf("in32 wrapped volume = %v, want 1000", s.Value)
	}
	if s, _ := find(b, "hcIn", "2", config.ModeRate); s.Value != 0.0 {
		t.Errorf("hcIn.2 rate = %v, want 0", s.Value)
	}
	if s, _ := find(b, "sysUpTime", "", config.ModeRate); s.Value != 100.0 {
		t.Errorf("sysUpTime rate = %v, want 100", s.Value)
	}

	// Poll 3: discovery interval elapsed, state is wiped, no rates.
	clk.advance(time.Hour)
	res, err = d.poll(context.Background(), store, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.discovered {
		t.Error("poll 3 must rediscover")
	}
	if _, ok := find(out.batches[2], "hcIn", "1", config.ModeRate); ok {
		t.Error("rates must restart after rediscovery")
	}
}

func TestV1MissingOID(t *testing.T) {
	agent := testagent.Start(t, nil, testagent.NewMIB(sysMIB("v1")), nil)
	out := &capture{}
	d, store := newDevice(t, fmt.Sprintf(`
devices:
  - id: dev
    address: 127.0.0.1
    port: %d
    snmp: { version: 1, community: %s }
    scalars:
      - { name: a, oid: 1.3.6.1.2.1.1.77.0 }
      - { name: up, oid: 1.3.6.1.2.1.1.3.0 }
      - { name: b, oid: 1.3.6.1.2.1.1.78.0 }
`, agent.Port, testagent.Community), out)
	res, err := d.poll(context.Background(), store, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := find(out.batches[0], "up", "", config.ModeRaw); !ok || res.missing != 2 {
		t.Errorf("v1 must still return existing OIDs: %+v missing=%d", out.batches[0].Samples, res.missing)
	}
}

// TestRun runs the scheduler end to end with real time.
func TestRun(t *testing.T) {
	agent := testagent.Start(t, nil, testagent.NewMIB(sysMIB("run")), nil)
	dir := t.TempDir()
	stale := filepath.Join(dir, "data", "stale-device")
	os.MkdirAll(stale, 0o755)

	cfg, err := config.Parse(strings.NewReader(fmt.Sprintf(`
global: { poll_interval: 1s, stats_interval: 1s, data_dir: %s }
outputs: [{ name: cap, type: "null" }]
devices:
  - { id: ok1, address: 127.0.0.1, port: %[2]d, snmp: { version: 2c, community: %[3]s }, scalars: [{ name: up, oid: 1.3.6.1.2.1.1.3.0 }] }
  - { id: ok2, address: 127.0.0.1, port: %[2]d, snmp: { version: 2c, community: %[3]s }, scalars: [{ name: up, oid: 1.3.6.1.2.1.1.3.0 }] }
  - { id: bad, address: 127.0.0.1, port: %[2]d, timeout: 200ms, retries: 0, snmp: { version: 2c, community: very-secret-value }, scalars: [{ name: up, oid: 1.3.6.1.2.1.1.3.0 }] }
`, filepath.Join(dir, "data"), agent.Port, testagent.Community)))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}), nil))
	out := &capture{}
	p, err := New(cfg, log, map[string]output.Output{"cap": out})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("data dir must be cleaned on startup")
	}
	for _, id := range []string{"ok1", "ok2"} {
		if n := out.count(id); n < 3 {
			t.Errorf("%s polled %d times, want >= 3", id, n)
		}
	}
	logMu.Lock()
	text := logs.String()
	logMu.Unlock()
	if strings.Contains(text, "very-secret-value") || strings.Contains(text, testagent.Community) {
		t.Error("credentials found in logs")
	}
	if n := strings.Count(text, `msg="poll failed"`); n != 1 {
		t.Errorf("failing device logged %d times at warn, want exactly 1:\n%s", n, text)
	}
	if !strings.Contains(text, `msg="poller stats"`) || !strings.Contains(text, "failing_devices=1") {
		t.Errorf("stats line missing or wrong:\n%s", text)
	}
}

// With no enabled device the poller must keep running until asked to stop,
// not start shutting down immediately.
func TestRunNoDevices(t *testing.T) {
	cfg, err := config.Parse(strings.NewReader(fmt.Sprintf(
		`global: { data_dir: %s }`, filepath.Join(t.TempDir(), "data"))))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}), nil))
	p, err := New(cfg, log, map[string]output.Output{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	time.Sleep(200 * time.Millisecond)
	logMu.Lock()
	early := logs.String()
	logMu.Unlock()
	select {
	case err := <-done:
		t.Fatalf("Run returned before cancel: %v", err)
	default:
	}
	if strings.Contains(early, "poller stopping") {
		t.Errorf("poller stopping logged before any signal:\n%s", early)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestLessOID(t *testing.T) {
	idx := []string{"10", "2", "1.10", "1.2", "1"}
	sortIndexes(idx)
	if got := fmt.Sprint(idx); got != "[1 1.2 1.10 2 10]" {
		t.Errorf("sorted = %s", got)
	}
}
