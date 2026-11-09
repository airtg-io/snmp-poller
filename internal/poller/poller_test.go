package poller

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/gosnmp/gosnmp"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/sink"
	"github.com/airtg-io/snmp-poller/internal/state"
	"github.com/airtg-io/snmp-poller/internal/testagent"
	"github.com/airtg-io/snmp-poller/internal/testconf"
)

func loadDiscovery(t *testing.T, store *state.Store, id string) *Discovery {
	t.Helper()
	disc := &Discovery{}
	if err := store.LoadDiscovery(id, disc); err != nil {
		t.Fatalf("discovery cache: %v", err)
	}
	return disc
}

// capture is a sink that records batches, for tests.
type capture struct {
	mu      sync.Mutex
	batches []*sink.Batch
}

func (c *capture) Write(b *sink.Batch) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, b)
}
func (c *capture) Start()            {}
func (c *capture) Stats() sink.Stats { return sink.Stats{} }
func (c *capture) Close() error      { return nil }

// testSink is the sink of test configurations: the poller gets the fakes
// of testSinks instead.
const testSink = `sinks: [{ id: cap, type: prometheus, url: "http://sink.invalid/api/v1/write" }]`

// testSinks makes the poller use fake sinks, by id.
func testSinks(fakes map[string]Sink) Option {
	return WithSinkFactory(func(cfg config.Sink, _ string, _ *slog.Logger) (Sink, error) {
		if s, ok := fakes[cfg.ID]; ok {
			return s, nil
		}
		return newCounting(cfg.Headers["tag"]), nil
	})
}

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
		"1.3.6.1.2.1.1.4.0": {Type: gosnmp.OctetString, Value: "noc@example.net"},
		"1.3.6.1.2.1.1.5.0": {Type: gosnmp.OctetString, Value: name},
		"1.3.6.1.2.1.1.6.0": {Type: gosnmp.OctetString, Value: "rack 1"},
	}
}

// interfacesMIB has three interfaces: 10G (ifSpeed saturated), 1G and
// 100M, in ifTable. names adds the ifXTable names and an ENTITY-MIB chassis,
// counters the ifXTable 64-bit counters and ifHighSpeed.
func interfacesMIB(names, counters bool) *testagent.MIB {
	vals := sysMIB("sw")
	for i, row := range []struct {
		descr string
		speed uint32
	}{{"TenGigE0/1", math.MaxUint32}, {"GigE0/2", 1_000_000_000}, {"FastE0/3", 100_000_000}} {
		idx := i + 1
		set := func(oid string, typ gosnmp.Asn1BER, v any) {
			vals[fmt.Sprintf("%s.%d", oid, idx)] = testagent.Value{Type: typ, Value: v}
		}
		set("1.3.6.1.2.1.2.2.1.2", gosnmp.OctetString, row.descr)
		set("1.3.6.1.2.1.2.2.1.5", gosnmp.Gauge32, uint(row.speed))
		for _, col := range []string{"7", "8"} {
			set("1.3.6.1.2.1.2.2.1."+col, gosnmp.Integer, 1)
		}
		for _, col := range []string{"10", "11", "13", "14", "16", "17", "19", "20"} {
			set("1.3.6.1.2.1.2.2.1."+col, gosnmp.Counter32, uint(1000))
		}
		if names {
			set("1.3.6.1.2.1.31.1.1.1.1", gosnmp.OctetString, fmt.Sprintf("if%d", idx))
			set("1.3.6.1.2.1.31.1.1.1.18", gosnmp.OctetString, "uplink")
		}
		if counters {
			for _, col := range []string{"6", "7", "10", "11"} {
				set("1.3.6.1.2.1.31.1.1.1."+col, gosnmp.Counter64, uint64(1000))
			}
			set("1.3.6.1.2.1.31.1.1.1.15", gosnmp.Gauge32, uint(row.speed/1_000_000))
		}
	}
	if names {
		vals["1.3.6.1.2.1.47.1.1.1.1.7.1"] = testagent.Value{Type: gosnmp.OctetString, Value: "Chassis"}
		vals["1.3.6.1.2.1.47.1.1.1.1.11.1"] = testagent.Value{Type: gosnmp.OctetString, Value: "SN123"}
		vals["1.3.6.1.2.1.47.1.1.1.1.13.1"] = testagent.Value{Type: gosnmp.OctetString, Value: "SW-48"}
	}
	return testagent.NewMIB(vals)
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

// systemCap is the system group, as discovery scalars.
const systemCap = `
discovery:
  scalars:
    sysDescr: 1.3.6.1.2.1.1.1.0
    sysObjectID: 1.3.6.1.2.1.1.2.0
    sysName: 1.3.6.1.2.1.1.5.0
`

// basicCaps are the capabilities used by most tests.
var basicCaps = map[string]string{"system": systemCap, "uptime": testconf.Uptime}

func newDevice(t *testing.T, doc string, caps map[string]string, out Sink) (*device, *state.Store) {
	t.Helper()
	return deviceFrom(t, testconf.Parse(t, doc, caps), out)
}

// shippedDevice uses the capabilities shipped in etc/capabilities.d.
func shippedDevice(t *testing.T, doc string, out Sink) (*device, *state.Store) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	cfg, err := config.Parse(strings.NewReader(doc), filepath.Join(filepath.Dir(file), "..", "..", "etc"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return deviceFrom(t, cfg, out)
}

func deviceFrom(t *testing.T, cfg *config.Config, out Sink) (*device, *state.Store) {
	t.Helper()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &device{
		spec:  cfg.DeviceSpecs()[0],
		log:   slog.New(slog.DiscardHandler),
		sinks: []Sink{out},
	}, store
}

func find(b *sink.Batch, metric, idx string, mode config.Mode) (sink.Sample, bool) {
	for _, s := range b.Samples {
		if s.Metric == metric && s.Index == idx && s.Mode == mode {
			return s, true
		}
	}
	return sink.Sample{}, false
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
		cases["v3-authNoPriv-"+an] = fmt.Sprintf(`version: 3, username: a-%s, auth_protocol: %s, auth_password: %s`,
			an, an, testagent.AuthPass)
		for pn, pp := range privs {
			u := "ap-" + an + "-" + pn
			users = append(users, testagent.User{Name: u, Auth: ap, Priv: pp})
			cases["v3-authPriv-"+an+"-"+pn] = fmt.Sprintf(
				`version: 3, username: %s, auth_protocol: %s, auth_password: %s, priv_protocol: %s, priv_password: %s`,
				u, an, testagent.AuthPass, pn, testagent.PrivPass)
		}
	}
	agent := testagent.Start(t, users, testagent.NewMIB(sysMIB("default")),
		map[string]*testagent.MIB{"ctx1": testagent.NewMIB(sysMIB("in-ctx1"))})
	cases["v3-context"] = fmt.Sprintf(`version: 3, username: ap-SHA256-AES, auth_protocol: SHA256, auth_password: %s, priv_protocol: AES, priv_password: %s, context_name: ctx1`,
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
`, agent.Port, snmpCfg), basicCaps, out)
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
		"community": `version: 2c, community: wrong`,
		"password":  `version: 3, username: u, auth_protocol: SHA, auth_password: wrong-pass, priv_protocol: AES, priv_password: ` + testagent.PrivPass,
	} {
		t.Run(name, func(t *testing.T) {
			d, store := newDevice(t, fmt.Sprintf(`
devices:
  - { id: dev, address: 127.0.0.1, port: %d, timeout: 300ms, retries: 0, snmp: { %s } }
`, agent.Port, snmpCfg), basicCaps, &capture{})
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
`, agent.Port, testagent.Community), map[string]string{
		"system": systemCap,
		"metrics": `
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
`}, out)
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
	disc := loadDiscovery(t, store, "router")
	if got := fmt.Sprint(disc.Tables["if"].Rows); got != "[1 2]" {
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

// TestShippedInterfaces polls agents with and without ifXTable using the
// capabilities shipped in etc/capabilities.d.
func TestShippedInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name, include, caps, rows string
		names, counters           bool
	}{
		{name: "ifXTable", names: true, counters: true, caps: "[entity interfaces system]", rows: "[1 2 3]"},
		// Some agents have ifXTable names without its 64-bit counters.
		{name: "ifXTable names only", names: true, caps: "[entity interfaces system]", rows: "[1 2 3]"},
		{name: "ifTable only", include: `include: { interfaces: ["^(Ten|Gig)"] }`,
			caps: "[interfaces system]", rows: "[1 2]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range []struct{ version, walk string }{{"1", ""}, {"2c", ""}, {"2c", "getnext"}} {
				version := v.version
				t.Run("v"+version+v.walk, func(t *testing.T) {
					// SNMPv1 cannot carry Counter64: never high capacity.
					hc, hcRows := tc.counters && version != "1", "[]"
					if hc {
						hcRows = "[1 2]" // 10G and 1G, not 100M
					}
					agent := testagent.Start(t, nil, interfacesMIB(tc.names, tc.counters), nil)
					walk := "# walk inherited"
					if v.walk != "" {
						walk = "walk: " + v.walk
					}
					out := &capture{}
					d, store := shippedDevice(t, fmt.Sprintf(`
devices:
  - id: sw
    address: 127.0.0.1
    port: %d
    %s
    snmp: { version: "%s", community: %s }
    %s
`, agent.Port, walk, version, testagent.Community, tc.include), out)
					clk := &clock{t: time.Unix(1_700_000_000, 0)}
					for range 2 {
						res, err := d.poll(context.Background(), store, clk.now)
						if err != nil {
							t.Fatal(err)
						}
						if res.missing != 0 {
							t.Errorf("missing oids = %d, want 0", res.missing)
						}
						clk.advance(time.Minute)
					}

					// GETBULK unless walking with getnext, or on SNMPv1 (bulk
					// is then the inherited default, not an explicit setting).
					if bulk := agent.BulkRequests(); (bulk > 0) != (version != "1" && v.walk == "") {
						t.Errorf("GETBULK requests = %d", bulk)
					}

					disc := loadDiscovery(t, store, "sw")
					if got := fmt.Sprint(disc.Capabilities); got != tc.caps {
						t.Errorf("capabilities = %s, want %s", got, tc.caps)
					}
					for _, k := range []string{"sysDescr", "sysObjectID", "sysUpTime", "sysContact", "sysName", "sysLocation"} {
						if disc.Scalars[k] == "" {
							t.Errorf("discovery scalar %s not cached: %v", k, disc.Scalars)
						}
					}
					ifs := disc.Tables["interfaces"]
					if fmt.Sprint(ifs.Rows) != tc.rows || ifs.HighCapacity != hc ||
						fmt.Sprint(append([]string{}, ifs.HighCapacityRows...)) != hcRows {
						t.Errorf("interfaces discovery = %+v, want rows %s, high capacity %v on %s", ifs, tc.rows, hc, hcRows)
					}
					if tc.names && disc.Columns["entPhysicalModelName"]["1"] != "SW-48" {
						t.Errorf("entity not discovered: %v", disc.Columns)
					}

					b := out.batches[1]
					if fmt.Sprint(b.Capabilities) != tc.caps || b.Discovery["sysLocation"] != "rack 1" {
						t.Errorf("batch capabilities %v, discovery %v", b.Capabilities, b.Discovery)
					}
					wantType := map[string]string{"1": "Counter32", "2": "Counter32", "3": "Counter32"}
					if hc {
						wantType["1"], wantType["2"] = "Counter64", "Counter64"
					}
					if !strings.Contains(tc.rows, "3") {
						delete(wantType, "3") // filtered out by the device's include
					}
					highSpeed := map[string]uint64{"1": 4294, "2": 1000}
					if s, ok := find(b, "sysUpTime", "", config.ModeRaw); !ok || s.Type != "TimeTicks" {
						t.Errorf("sysUpTime must be polled every cycle: %+v", s)
					}
					for idx, typ := range wantType {
						for _, m := range []string{"ifInOctets", "ifOutOctets", "ifInUcastPkts", "ifOutUcastPkts"} {
							s, ok := find(b, m, idx, config.ModeRate)
							if !ok || s.Type != typ || s.Value != 0.0 {
								t.Errorf("%s.%s rate = %+v (found %v), want type %s", m, idx, s, ok, typ)
							}
						}
						if s, ok := find(b, "ifInErrors", idx, config.ModeVolume); !ok || s.Type != "Counter32" {
							t.Errorf("ifInErrors.%s = %+v", idx, s)
						}
						s, ok := find(b, "ifHighSpeed", idx, config.ModeRaw)
						if wantHC := typ == "Counter64"; ok != wantHC || (ok && s.Value != highSpeed[idx]) {
							t.Errorf("ifHighSpeed.%s = %+v (found %v), want only on high-capacity rows", idx, s, ok)
						}
					}
					s, _ := find(b, "ifOperStatus", "1", config.ModeRaw)
					if s.Labels["ifDescr"] != "TenGigE0/1" {
						t.Errorf("labels = %v", s.Labels)
					}
					if tc.names && (s.Labels["ifName"] != "if1" || s.Labels["ifAlias"] != "uplink") {
						t.Errorf("ifXTable labels = %v", s.Labels)
					}
				})
			}
		})
	}
}

// hostMIB is a host with HOST-RESOURCES-MIB: up 50 s while its agent is up
// 10 s, 2 MiB of memory (in KiB), three storages with different allocation
// units (one of size 0) and two processors.
func hostMIB() *testagent.MIB {
	vals := sysMIB("host")
	set := func(oid string, typ gosnmp.Asn1BER, v any) { vals[oid] = testagent.Value{Type: typ, Value: v} }
	set("1.3.6.1.2.1.25.1.1.0", gosnmp.TimeTicks, uint32(5000))
	set("1.3.6.1.2.1.25.1.6.0", gosnmp.Gauge32, uint(42))
	set("1.3.6.1.2.1.25.2.2.0", gosnmp.Integer, 2048)
	for _, row := range []struct {
		idx, descr       string
		units, size, use int
	}{
		{"1", "Physical memory", 1024, 2048, 512},
		{"31", "/", 4096, math.MaxInt32, 1000}, // 8 TiB: exact product needed
		{"40", "/empty", 4096, 0, 0},
	} {
		set("1.3.6.1.2.1.25.2.3.1.2."+row.idx, gosnmp.ObjectIdentifier, "1.3.6.1.2.1.25.2.1.4")
		set("1.3.6.1.2.1.25.2.3.1.3."+row.idx, gosnmp.OctetString, row.descr)
		set("1.3.6.1.2.1.25.2.3.1.4."+row.idx, gosnmp.Integer, row.units)
		set("1.3.6.1.2.1.25.2.3.1.5."+row.idx, gosnmp.Integer, row.size)
		set("1.3.6.1.2.1.25.2.3.1.6."+row.idx, gosnmp.Integer, row.use)
	}
	// hrDeviceTable has more rows than hrProcessorTable.
	set("1.3.6.1.2.1.25.3.2.1.3.196608", gosnmp.OctetString, "CPU0")
	set("1.3.6.1.2.1.25.3.2.1.3.196609", gosnmp.OctetString, "CPU1")
	set("1.3.6.1.2.1.25.3.2.1.3.262145", gosnmp.OctetString, "network interface lo")
	set("1.3.6.1.2.1.25.3.3.1.2.196608", gosnmp.Integer, 10)
	set("1.3.6.1.2.1.25.3.3.1.2.196609", gosnmp.Integer, 20)
	return testagent.NewMIB(vals)
}

// TestShippedHostResources polls hosts with and without HOST-RESOURCES-MIB
// using the shipped capabilities: uptime source, formulas, inputs only.
func TestShippedHostResources(t *testing.T) {
	for _, version := range []string{"1", "2c"} {
		t.Run("v"+version, func(t *testing.T) {
			t.Run("host", func(t *testing.T) {
				agent := testagent.Start(t, nil, hostMIB(), nil)
				out := &capture{}
				d, store := shippedDevice(t, fmt.Sprintf(`
devices: [{ id: host, address: 127.0.0.1, port: %d, snmp: { version: "%s", community: %s } }]
`, agent.Port, version, testagent.Community), out)
				res, err := d.poll(context.Background(), store, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				if res.missing != 0 {
					t.Errorf("missing oids = %d, want 0", res.missing)
				}
				disc := loadDiscovery(t, store, "host")
				if got := fmt.Sprint(disc.Capabilities); got != "[host-resources interfaces system]" {
					t.Errorf("capabilities = %s", got)
				}
				if got := disc.Sources["uptime"]; got != ".1.3.6.1.2.1.25.1.1.0" {
					t.Errorf("uptime source = %q, want hrSystemUptime", got)
				}
				b := out.batches[0]
				type want struct {
					idx   string
					value any
					unit  string
				}
				for metric, w := range map[string]want{
					"uptime":            {"", uint64(5000), "centiseconds"}, // hrSystemUptime
					"sysUpTime":         {"", uint64(1000), "centiseconds"}, // the agent
					"hrSystemProcesses": {"", uint64(42), "processes"},
					"memorySize":        {"", int64(2048 * 1024), "bytes"},
				} {
					if s, ok := find(b, metric, w.idx, config.ModeRaw); !ok || s.Value != w.value || s.Unit != w.unit {
						t.Errorf("%s = %+v (found %v), want %v %s", metric, s, ok, w.value, w.unit)
					}
				}
				for _, w := range []struct {
					metric, idx string
					value       any // nil: no sample
				}{
					{"storageSize", "1", int64(2048 * 1024)},
					{"storageUsed", "1", int64(512 * 1024)},
					{"storageFree", "1", int64(1536 * 1024)},
					{"storageUsedPercent", "1", 25.0},
					{"storageFreePercent", "1", 75.0},
					{"storageSize", "31", int64(math.MaxInt32) * 4096},
					{"storageFree", "31", int64(math.MaxInt32-1000) * 4096},
					{"storageSize", "40", int64(0)},
					{"storageFree", "40", int64(0)},
					{"storageUsedPercent", "40", nil}, // division by zero
					{"storageFreePercent", "40", nil},
				} {
					s, ok := find(b, w.metric, w.idx, config.ModeRaw)
					if ok != (w.value != nil) || (ok && (s.Value != w.value || s.Type != sink.TypeFormula)) {
						t.Errorf("%s.%s = %+v (found %v), want %v", w.metric, w.idx, s, ok, w.value)
					}
				}
				if s, _ := find(b, "storageUsedPercent", "1", config.ModeRaw); s.Unit != "percent" ||
					s.Labels["hrStorageDescr"] != "Physical memory" || s.Labels["hrStorageType"] != ".1.3.6.1.2.1.25.2.1.4" {
					t.Errorf("storage sample = %+v", s)
				}
				// Inputs of formulas are polled but not emitted.
				for _, m := range []string{"hrMemorySize", "hrStorageAllocationUnits", "hrStorageSize", "hrStorageUsed"} {
					for _, s := range b.Samples {
						if s.Metric == m {
							t.Errorf("input %s emitted: %+v", m, s)
						}
					}
				}
				var cpus []string
				for _, s := range b.Samples {
					if s.Metric == "hrProcessorLoad" {
						cpus = append(cpus, fmt.Sprintf("%s=%v%%(%s)", s.Index, s.Value, s.Labels["hrDeviceDescr"]))
					}
				}
				if got := fmt.Sprint(cpus); got != "[196608=10%(CPU0) 196609=20%(CPU1)]" {
					t.Errorf("processors = %s", got)
				}
			})
			// Without HOST-RESOURCES-MIB, uptime falls back to sysUpTime.
			t.Run("network device", func(t *testing.T) {
				agent := testagent.Start(t, nil, testagent.NewMIB(sysMIB("sw")), nil)
				out := &capture{}
				d, store := shippedDevice(t, fmt.Sprintf(`
devices: [{ id: sw, address: 127.0.0.1, port: %d, snmp: { version: "%s", community: %s } }]
`, agent.Port, version, testagent.Community), out)
				res, err := d.poll(context.Background(), store, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				if res.missing != 0 {
					t.Errorf("missing oids = %d, want 0", res.missing)
				}
				disc := loadDiscovery(t, store, "sw")
				if got := fmt.Sprint(disc.Capabilities); got != "[interfaces system]" {
					t.Errorf("capabilities = %s", got)
				}
				if s, ok := find(out.batches[0], "uptime", "", config.ModeRaw); !ok || s.Value != uint64(1000) {
					t.Errorf("uptime = %+v (found %v), want sysUpTime", s, ok)
				}
			})
		})
	}
}

// ciscoMIB is the multi-CPU chassis of Cisco's document 15215: an RSP and
// two line cards, each pointing to its ENTITY-MIB entry, plus a CPU without
// entity (cpmCPUTotalPhysicalIndex 0). The deprecated columns are there too.
func ciscoMIB() *testagent.MIB {
	vals := sysMIB("rtr")
	set := func(oid string, typ gosnmp.Asn1BER, v any) { vals[oid] = testagent.Value{Type: typ, Value: v} }
	for idx, name := range map[string]string{"1": "Chassis", "9": "RSP at Slot 2", "25": "Line Card 4", "28": "Line Card 6"} {
		set("1.3.6.1.2.1.47.1.1.1.1.7."+idx, gosnmp.OctetString, name)
	}
	const cpm = "1.3.6.1.4.1.9.9.109.1.1.1.1."
	for _, row := range []struct {
		idx                    string
		phys, sec5, min1, min5 int
	}{
		{"1", 9, 12, 11, 10},
		{"8", 25, 3, 2, 1},
		{"9", 28, 4, 3, 2},
		{"10", 0, 50, 40, 30},
	} {
		set(cpm+"2."+row.idx, gosnmp.Integer, row.phys)
		for col, v := range map[string]int{"3": 99, "4": 99, "5": 99, "6": row.sec5, "7": row.min1, "8": row.min5} {
			set(cpm+col+"."+row.idx, gosnmp.Gauge32, uint(v))
		}
	}
	return testagent.NewMIB(vals)
}

// TestShippedCiscoCPU polls the shipped cisco-cpu capability: one row per
// CPU, named by the entPhysicalName its cpmCPUTotalPhysicalIndex points to,
// "Rev" objects only.
func TestShippedCiscoCPU(t *testing.T) {
	for _, version := range []string{"1", "2c"} {
		t.Run("v"+version, func(t *testing.T) {
			agent := testagent.Start(t, nil, ciscoMIB(), nil)
			out := &capture{}
			d, store := shippedDevice(t, fmt.Sprintf(`
devices: [{ id: rtr, address: 127.0.0.1, port: %d, snmp: { version: "%s", community: %s } }]
`, agent.Port, version, testagent.Community), out)
			res, err := d.poll(context.Background(), store, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if res.missing != 0 {
				t.Errorf("missing oids = %d, want 0", res.missing)
			}
			disc := loadDiscovery(t, store, "rtr")
			if got := fmt.Sprint(disc.Capabilities); got != "[cisco-cpu interfaces system]" {
				t.Errorf("capabilities = %s", got)
			}
			if got := fmt.Sprint(disc.Columns["cpuName"]); got != "map[1:RSP at Slot 2 8:Line Card 4 9:Line Card 6]" {
				t.Errorf("cpuName = %s", got)
			}
			var cpus []string
			for _, s := range out.batches[0].Samples {
				if s.Table != "cpu" {
					continue
				}
				if s.Unit != "percent" || s.Capability != "cisco-cpu" {
					t.Errorf("sample = %+v", s)
				}
				cpus = append(cpus, fmt.Sprintf("%s.%s=%v(%s,%s)", s.Metric, s.Index, s.Value,
					s.Labels["cpuName"], s.Labels["cpmCPUTotalPhysicalIndex"]))
			}
			slices.Sort(cpus)
			want := []string{
				"cpmCPUTotal1minRev.1=11(RSP at Slot 2,9)",
				"cpmCPUTotal1minRev.10=40(,0)",
				"cpmCPUTotal1minRev.8=2(Line Card 4,25)",
				"cpmCPUTotal1minRev.9=3(Line Card 6,28)",
				"cpmCPUTotal5minRev.1=10(RSP at Slot 2,9)",
				"cpmCPUTotal5minRev.10=30(,0)",
				"cpmCPUTotal5minRev.8=1(Line Card 4,25)",
				"cpmCPUTotal5minRev.9=2(Line Card 6,28)",
				"cpmCPUTotal5secRev.1=12(RSP at Slot 2,9)",
				"cpmCPUTotal5secRev.10=50(,0)",
				"cpmCPUTotal5secRev.8=3(Line Card 4,25)",
				"cpmCPUTotal5secRev.9=4(Line Card 6,28)",
			}
			slices.Sort(want)
			if !slices.Equal(cpus, want) {
				t.Errorf("cpu samples =\n%s\nwant\n%s", strings.Join(cpus, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// ciscoMemMIB has the memory pools of a chassis: CISCO-ENHANCED-MEMPOOL-MIB
// (enhanced; hc adds its 64-bit columns) with a 6 GiB processor pool on the
// route processor, an I/O pool and a line card pool, and/or
// CISCO-MEMORY-POOL-MIB (old), its 32-bit view.
func ciscoMemMIB(enhanced, hc, old bool) *testagent.MIB {
	vals := sysMIB("rtr")
	set := func(oid string, typ gosnmp.Asn1BER, v any) { vals[oid] = testagent.Value{Type: typ, Value: v} }
	set("1.3.6.1.2.1.47.1.1.1.1.7.22", gosnmp.OctetString, "RP0")
	set("1.3.6.1.2.1.47.1.1.1.1.7.1000", gosnmp.OctetString, "Line Card 1")
	const gib = uint64(1) << 30
	for _, row := range []struct {
		idx, name  string
		used, free uint64
	}{
		{"22.1", "Processor", 6 * gib, 2 * gib},
		{"22.2", "I/O", 300, 700},
		{"1000.1", "Processor", 1000, 3000},
	} {
		if !enhanced {
			break
		}
		const cemp = "1.3.6.1.4.1.9.9.221.1.1.1.1."
		set(cemp+"3."+row.idx, gosnmp.OctetString, row.name)
		set(cemp+"7."+row.idx, gosnmp.Gauge32, uint(uint32(row.used))) // low 32 bits
		set(cemp+"8."+row.idx, gosnmp.Gauge32, uint(uint32(row.free)))
		set(cemp+"9."+row.idx, gosnmp.Gauge32, uint(uint32(row.free/2)))
		if hc {
			set(cemp+"18."+row.idx, gosnmp.Counter64, row.used)
			set(cemp+"20."+row.idx, gosnmp.Counter64, row.free)
			set(cemp+"22."+row.idx, gosnmp.Counter64, row.free/2)
		}
	}
	if old {
		const cmp = "1.3.6.1.4.1.9.9.48.1.1.1."
		for _, row := range []struct {
			idx, name  string
			used, free uint
		}{{"1", "Processor", 3_000_000, 1_000_000}, {"2", "I/O", 300, 700}} {
			set(cmp+"2."+row.idx, gosnmp.OctetString, row.name)
			set(cmp+"5."+row.idx, gosnmp.Gauge32, row.used)
			set(cmp+"6."+row.idx, gosnmp.Gauge32, row.free)
			set(cmp+"7."+row.idx, gosnmp.Gauge32, row.free/2)
		}
	}
	return testagent.NewMIB(vals)
}

// TestShippedCiscoMemory polls the shipped memory capabilities:
// cisco-enhanced-mempool is preferred, cisco-memory-pool is its fallback
// (also when the device excludes the enhanced one), 64-bit columns are used
// when the agent has them, except over SNMPv1.
func TestShippedCiscoMemory(t *testing.T) {
	for _, tc := range []struct {
		name              string
		version           string
		enhanced, hc, old bool
		exclude           string
		caps              string
		want              []string // memory samples, sorted
	}{
		{"both MIBs, 64-bit", "2c", true, true, true, "", "[cisco-enhanced-mempool interfaces system]", []string{
			"cempMemPoolFree.1000.1=3000 Counter64 (Processor,Line Card 1,1000)",
			"cempMemPoolFree.22.1=2147483648 Counter64 (Processor,RP0,22)",
			"cempMemPoolFree.22.2=700 Counter64 (I/O,RP0,22)",
			"cempMemPoolLargestFree.1000.1=1500 Counter64 (Processor,Line Card 1,1000)",
			"cempMemPoolLargestFree.22.1=1073741824 Counter64 (Processor,RP0,22)",
			"cempMemPoolLargestFree.22.2=350 Counter64 (I/O,RP0,22)",
			"cempMemPoolUsed.1000.1=1000 Counter64 (Processor,Line Card 1,1000)",
			"cempMemPoolUsed.22.1=6442450944 Counter64 (Processor,RP0,22)",
			"cempMemPoolUsed.22.2=300 Counter64 (I/O,RP0,22)",
			"cempMemPoolUsedPercent.1000.1=25 Formula (Processor,Line Card 1,1000)",
			"cempMemPoolUsedPercent.22.1=75 Formula (Processor,RP0,22)",
			"cempMemPoolUsedPercent.22.2=30 Formula (I/O,RP0,22)",
		}},
		// The 32-bit view of the 6 GiB pool is wrong: what 64-bit columns are for.
		{"enhanced, 32-bit only", "2c", true, false, false, "", "[cisco-enhanced-mempool interfaces system]", []string{
			"cempMemPoolUsed.22.1=2147483648 Gauge32 (Processor,RP0,22)",
		}},
		{"enhanced over SNMPv1", "1", true, true, false, "", "[cisco-enhanced-mempool interfaces system]", []string{
			"cempMemPoolUsed.22.1=2147483648 Gauge32 (Processor,RP0,22)",
		}},
		{"memory pool only", "2c", false, false, true, "", "[cisco-memory-pool interfaces system]", []string{
			"ciscoMemoryPoolFree.1=1000000 Gauge32 (Processor,,)",
			"ciscoMemoryPoolFree.2=700 Gauge32 (I/O,,)",
			"ciscoMemoryPoolLargestFree.1=500000 Gauge32 (Processor,,)",
			"ciscoMemoryPoolLargestFree.2=350 Gauge32 (I/O,,)",
			"ciscoMemoryPoolUsed.1=3000000 Gauge32 (Processor,,)",
			"ciscoMemoryPoolUsed.2=300 Gauge32 (I/O,,)",
			"ciscoMemoryPoolUsedPercent.1=75 Formula (Processor,,)",
			"ciscoMemoryPoolUsedPercent.2=30 Formula (I/O,,)",
		}},
		{"both MIBs, enhanced excluded", "2c", true, true, true, "cisco-enhanced-mempool", "[cisco-memory-pool interfaces system]", []string{
			"ciscoMemoryPoolUsed.1=3000000 Gauge32 (Processor,,)",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := testagent.Start(t, nil, ciscoMemMIB(tc.enhanced, tc.hc, tc.old), nil)
			out := &capture{}
			d, store := shippedDevice(t, fmt.Sprintf(`
devices: [{ id: rtr, address: 127.0.0.1, port: %d, exclude: [%s], snmp: { version: "%s", community: %s } }]
`, agent.Port, tc.exclude, tc.version, testagent.Community), out)
			res, err := d.poll(context.Background(), store, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if res.missing != 0 {
				t.Errorf("missing oids = %d, want 0", res.missing)
			}
			if got := fmt.Sprint(loadDiscovery(t, store, "rtr").Capabilities); got != tc.caps {
				t.Errorf("capabilities = %s, want %s", got, tc.caps)
			}
			got := map[string]bool{}
			for _, s := range out.batches[0].Samples {
				if s.Table != "enhanced_mempool" && s.Table != "memory_pool" {
					continue
				}
				if want := "bytes"; strings.HasSuffix(s.Metric, "Percent") {
					want = "percent"
					if s.Unit != want {
						t.Errorf("%s unit = %q", s.Metric, s.Unit)
					}
				} else if s.Unit != want {
					t.Errorf("%s unit = %q", s.Metric, s.Unit)
				}
				got[fmt.Sprintf("%s.%s=%v %s (%s%s,%s,%s)", s.Metric, s.Index, s.Value, s.Type,
					s.Labels["cempMemPoolName"], s.Labels["ciscoMemoryPoolName"],
					s.Labels["mempoolEntityName"], s.Labels["mempoolPhysicalIndex"])] = true
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing sample %s", w)
				}
			}
			if n := len(tc.want); n > 1 && len(got) != n {
				t.Errorf("%d memory samples, want %d:\n%s", len(got), n, strings.Join(slices.Sorted(maps.Keys(got)), "\n"))
			}
		})
	}
}

// TestFormulas covers formulas on walked tables, missing inputs, emit:
// false and unit suffixes on rates, with custom capabilities.
func TestFormulas(t *testing.T) {
	caps := map[string]string{"f": `
scalars:
  - { name: up, oid: 1.3.6.1.2.1.1.3.0, unit: centiseconds, modes: [raw, rate] }
  - { name: upSeconds, formula: "up / 100", unit: seconds }
  - { name: gone, oid: 1.3.6.1.2.1.1.99.0, emit: false }
  - { name: needsGone, formula: "gone + up" }
  - { name: name, oid: 1.3.6.1.2.1.1.5.0, emit: false }
  - { name: notNumber, formula: "name * 2" }
tables:
  - name: walked
    columns:
      - { name: v, oid: 1.3.6.1.2.1.25.2.3.1.6, emit: false }
      - { name: double, formula: "v * 2" }
`}
	agent := testagent.Start(t, nil, ifMIB(), nil)
	out := &capture{}
	d, store := newDevice(t, fmt.Sprintf(`
devices: [{ id: dev, address: 127.0.0.1, port: %d, snmp: { version: 2c, community: %s } }]
`, agent.Port, testagent.Community), caps, out)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	for range 2 {
		if _, err := d.poll(context.Background(), store, clk.now); err != nil {
			t.Fatal(err)
		}
		clk.advance(10 * time.Second)
	}
	b := out.batches[1]
	if s, ok := find(b, "upSeconds", "", config.ModeRaw); !ok || s.Value != 10.0 || s.Unit != "seconds" {
		t.Errorf("upSeconds = %+v (found %v)", s, ok)
	}
	if s, ok := find(b, "up", "", config.ModeRate); !ok || s.Unit != "centiseconds/s" {
		t.Errorf("up rate = %+v (found %v), want unit centiseconds/s", s, ok)
	}
	for _, m := range []string{"gone", "needsGone", "name", "notNumber", "v"} {
		for _, s := range b.Samples {
			if s.Metric == m {
				t.Errorf("%s emitted: %+v", m, s)
			}
		}
	}
	for idx, want := range map[string]int64{"1.1": 20, "2.1": 40} {
		if s, ok := find(b, "double", idx, config.ModeRaw); !ok || s.Value != want || s.Table != "walked" {
			t.Errorf("double.%s = %+v (found %v), want %d", idx, s, ok, want)
		}
	}
}

// TestCapabilityDetection covers detect (present, absent at the end of the
// MIB, absent with a following subtree) and exclude, on v1 and v2c.
func TestCapabilityDetection(t *testing.T) {
	caps := map[string]string{
		"always":   `scalars: [{ name: always, oid: 1.3.6.1.2.1.1.3.0 }]`,
		"present":  "detect: [1.3.6.1.2.1.1, 1.3.6.1.2.1.31.1.1.1.1]\nscalars: [{ name: present, oid: 1.3.6.1.2.1.1.3.0 }]",
		"partial":  "detect: [1.3.6.1.2.1.1, 1.3.6.1.2.1.88]\nscalars: [{ name: partial, oid: 1.3.6.1.2.1.1.3.0 }]",
		"next":     "detect: [1.3.6.1.2.1.1.50]\nscalars: [{ name: next, oid: 1.3.6.1.2.1.1.3.0 }]",
		"end":      "detect: [1.3.6.1.4.1.99999.1]\nscalars: [{ name: end, oid: 1.3.6.1.2.1.1.3.0 }]",
		"excluded": `scalars: [{ name: excluded, oid: 1.3.6.1.2.1.1.3.0 }]`,
	}
	agent := testagent.Start(t, nil, ifMIB(), nil)
	for _, version := range []string{"1", "2c"} {
		t.Run("v"+version, func(t *testing.T) {
			out := &capture{}
			d, store := newDevice(t, fmt.Sprintf(`
devices:
  - { id: dev, address: 127.0.0.1, port: %d, snmp: { version: "%s", community: %s }, exclude: [excluded] }
`, agent.Port, version, testagent.Community), caps, out)
			if _, err := d.poll(context.Background(), store, time.Now); err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprint(loadDiscovery(t, store, "dev").Capabilities); got != "[always present]" {
				t.Errorf("capabilities = %s, want [always present]", got)
			}
			for _, m := range []string{"always", "present", "partial", "next", "end", "excluded"} {
				_, ok := find(out.batches[0], m, "", config.ModeRaw)
				if want := m == "always" || m == "present"; ok != want {
					t.Errorf("%s polled = %v, want %v", m, ok, want)
				}
			}
		})
	}
}

// TestDiscoveryCache checks that polls between discoveries read the
// discovery from disk, and rediscover when the cache is gone.
func TestDiscoveryCache(t *testing.T) {
	agent := testagent.Start(t, nil, testagent.NewMIB(sysMIB("live")), nil)
	out := &capture{}
	d, store := newDevice(t, fmt.Sprintf(`
devices: [{ id: dev, address: 127.0.0.1, port: %d, snmp: { version: 2c, community: %s } }]
`, agent.Port, testagent.Community), basicCaps, out)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	poll := func() pollResult {
		t.Helper()
		res, err := d.poll(context.Background(), store, clk.now)
		if err != nil {
			t.Fatal(err)
		}
		clk.advance(time.Minute)
		return res
	}
	if !poll().discovered {
		t.Fatal("first poll must discover")
	}
	disc := loadDiscovery(t, store, "dev")
	disc.Scalars["sysName"] = "from-cache"
	if err := store.SaveDiscovery("dev", disc); err != nil {
		t.Fatal(err)
	}
	if poll().discovered {
		t.Error("second poll must use the cache")
	}
	if got := out.batches[1].Discovery["sysName"]; got != "from-cache" {
		t.Errorf("sysName = %q: discovery not read from disk", got)
	}
	if err := os.Remove(filepath.Join(store.DeviceDir("dev"), "discovery.json")); err != nil {
		t.Fatal(err)
	}
	if !poll().discovered {
		t.Error("missing cache must trigger a rediscovery")
	}
	if got := out.batches[2].Discovery["sysName"]; got != "live" {
		t.Errorf("sysName = %q after rediscovery", got)
	}
}

// TestSharedOID reads one OID from several metrics in several capabilities
// (scalars and walked tables): it is fetched once per poll, every metric gets
// its samples, and rate and volume share one previous value stored per OID.
func TestSharedOID(t *testing.T) {
	mib := ifMIB()
	agent := testagent.Start(t, nil, mib, nil)
	out := &capture{}
	d, store := newDevice(t, fmt.Sprintf(`
devices: [{ id: dev, address: 127.0.0.1, port: %d, snmp: { version: 2c, community: %s } }]
`, agent.Port, testagent.Community), map[string]string{
		"a": `
discovery: { scalars: { name1: 1.3.6.1.2.1.1.5.0 } }
scalars: [{ name: upA, oid: 1.3.6.1.2.1.1.3.0, modes: [raw, rate, volume] }]
tables: [{ name: storeA, columns: [{ name: usedA, oid: 1.3.6.1.2.1.25.2.3.1.6, modes: [volume] }] }]
`,
		"b": `
discovery: { scalars: { name2: 1.3.6.1.2.1.1.5.0 } }
scalars: [{ name: upB, oid: 1.3.6.1.2.1.1.3.0, modes: [rate] }]
tables: [{ name: storeB, include: ["^2\\."], columns: [{ name: usedB, oid: 1.3.6.1.2.1.25.2.3.1.6, modes: [raw, volume] }] }]
`,
	}, out)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	for i := range 2 {
		if _, err := d.poll(context.Background(), store, clk.now); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			clk.advance(10 * time.Second)
			mib.Set("1.3.6.1.2.1.1.3.0", uint32(2000))
			mib.Set("1.3.6.1.2.1.25.2.3.1.6.2.1", 25)
		}
	}
	disc := loadDiscovery(t, store, "dev")
	if disc.Scalars["name1"] != "router" || disc.Scalars["name2"] != "router" {
		t.Errorf("discovery scalars sharing an OID = %v", disc.Scalars)
	}
	b := out.batches[1]
	for _, w := range []struct {
		metric, idx string
		mode        config.Mode
		want        any
	}{
		{"upA", "", config.ModeRaw, uint64(2000)},
		{"upA", "", config.ModeRate, 100.0},
		{"upA", "", config.ModeVolume, 1000.0},
		{"upB", "", config.ModeRate, 100.0},
		{"usedA", "1.1", config.ModeVolume, 0.0},
		{"usedA", "2.1", config.ModeVolume, 5.0},
		{"usedB", "2.1", config.ModeRaw, int64(25)},
		{"usedB", "2.1", config.ModeVolume, 5.0},
	} {
		if s, ok := find(b, w.metric, w.idx, w.mode); !ok || s.Value != w.want {
			t.Errorf("%s.%s %s = %v (found %v), want %v", w.metric, w.idx, w.mode, s.Value, ok, w.want)
		}
	}
	if _, ok := find(b, "usedB", "1.1", config.ModeRaw); ok {
		t.Error("usedB must keep its own include filter")
	}
	if len(b.Samples) != 8 {
		t.Errorf("samples = %d, want 8: %+v", len(b.Samples), b.Samples)
	}
	data, err := os.ReadFile(filepath.Join(store.DeviceDir("dev"), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(slices.Sorted(maps.Keys(st))); got != "[.1.3.6.1.2.1.1.3.0 .1.3.6.1.2.1.25.2.3.1.6.1.1 .1.3.6.1.2.1.25.2.3.1.6.2.1]" {
		t.Errorf("state keys = %s, want one per OID", got)
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
`, agent.Port, testagent.Community), map[string]string{"v1": `
scalars:
  - { name: a, oid: 1.3.6.1.2.1.1.77.0 }
  - { name: up, oid: 1.3.6.1.2.1.1.3.0 }
  - { name: b, oid: 1.3.6.1.2.1.1.78.0 }
`}, out)
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
	// One agent per device: the same agent twice is an invalid configuration.
	var ports [3]uint16
	for i := range ports {
		ports[i] = testagent.Start(t, nil, testagent.NewMIB(sysMIB("run")), nil).Port
	}
	dir := t.TempDir()
	stale := filepath.Join(dir, "data", "stale-device")
	os.MkdirAll(stale, 0o755)

	cfg := testconf.Parse(t, fmt.Sprintf(`
global: { poll_interval: 1s, stats_interval: 1s, data_dir: %s }
%[6]s
devices:
  - { id: ok1, address: 127.0.0.1, port: %[2]d, snmp: { version: 2c, community: %[5]s } }
  - { id: ok2, address: 127.0.0.1, port: %[3]d, snmp: { version: 2c, community: %[5]s } }
  - { id: bad, address: 127.0.0.1, port: %[4]d, timeout: 200ms, retries: 0, snmp: { version: 2c, community: very-secret-value } }
`, filepath.Join(dir, "data"), ports[0], ports[1], ports[2], testagent.Community, testSink), basicCaps)
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}), nil))
	out := &capture{}
	p, err := New(cfg, log, testSinks(map[string]Sink{"cap": out}))
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
	cfg := testconf.Parse(t, fmt.Sprintf(`global: { data_dir: %s }`, filepath.Join(t.TempDir(), "data")), basicCaps)
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}), nil))
	p, err := New(cfg, log)
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

// fakeVault serves one secret, or an error.
type fakeVault struct {
	mu     sync.Mutex
	secret map[string]string
	err    error
	reads  []string
}

func (f *fakeVault) Read(_ context.Context, path string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, path)
	return maps.Clone(f.secret), f.err
}

// TestVaultCredentials: credentials are read at every discovery and only
// then; a failing refresh keeps the previous credentials.
func TestVaultCredentials(t *testing.T) {
	agent := testagent.Start(t, []testagent.User{{Name: "u", Auth: gosnmp.SHA, Priv: gosnmp.AES}},
		testagent.NewMIB(sysMIB("vaulted")), nil)
	doc := fmt.Sprintf(`
vault: { address: "https://vault.invalid", auth: { method: token, token: t0ken-value } }
devices:
  - { id: dev, address: 127.0.0.1, port: %d, timeout: 300ms, retries: 0, discovery_interval: 1h,
      snmp: { version: 3, vault: true } }
`, agent.Port)
	good := map[string]string{"username": "u", "auth_protocol": "SHA", "auth_password": testagent.AuthPass,
		"priv_protocol": "AES", "priv_password": testagent.PrivPass}

	out := &capture{}
	d, store := newDevice(t, doc, basicCaps, out)
	var logs bytes.Buffer
	d.log = slog.New(slog.NewTextHandler(&logs, nil))
	fv := &fakeVault{secret: good}
	d.vault = fv
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	poll := func() error {
		t.Helper()
		_, err := d.poll(context.Background(), store, clk.now)
		clk.advance(time.Minute)
		return err
	}

	if err := poll(); err != nil {
		t.Fatal(err)
	}
	if err := poll(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(fv.reads) != "[snmp-poller/dev]" {
		t.Errorf("reads = %v, want one at the first discovery only", fv.reads)
	}
	if out.batches[0].Discovery["sysName"] != "vaulted" {
		t.Errorf("batch = %+v", out.batches[0])
	}

	// Vault down at the next discovery: the previous credentials are kept.
	clk.advance(time.Hour)
	fv.err = errors.New("vault: connection refused")
	if err := poll(); err != nil {
		t.Fatalf("poll with previous credentials: %v", err)
	}
	if len(fv.reads) != 2 || !strings.Contains(logs.String(), `msg="credentials refresh failed, keeping the previous ones"`) {
		t.Errorf("reads = %v, logs:\n%s", fv.reads, logs.String())
	}

	// Rotated (here: wrong) credentials are applied at the next discovery.
	clk.advance(time.Hour)
	fv.err = nil
	fv.secret = maps.Clone(good)
	fv.secret["auth_password"] = "rotated-wrong-pass"
	if err := poll(); err == nil {
		t.Error("expected the new (wrong) credentials to be used")
	}
	if strings.Contains(logs.String(), "rotated-wrong") || strings.Contains(logs.String(), testagent.AuthPass) ||
		strings.Contains(logs.String(), "t0ken-value") {
		t.Errorf("credentials in logs:\n%s", logs.String())
	}

	// A device that never got credentials fails, with the Vault error.
	d2, store2 := newDevice(t, doc, basicCaps, &capture{})
	d2.vault = &fakeVault{err: errors.New("vault: GET secret/data/snmp-poller/dev: 403 permission denied")}
	if _, err := d2.poll(context.Background(), store2, time.Now); err == nil || !strings.Contains(err.Error(), "403 permission denied") {
		t.Errorf("err = %v", err)
	}
	d2.vault = &fakeVault{secret: map[string]string{"community": "c"}}
	if _, err := d2.poll(context.Background(), store2, time.Now); err == nil ||
		err.Error() != "vault secret snmp-poller/dev: snmp v3 requires a username" {
		t.Errorf("err = %v", err)
	}
}

// TestSinks runs the poller with the shipped capabilities and both sink
// types against fake destinations: what they receive carries the polled
// metrics and the tags chosen from the discovery cache.
func TestSinks(t *testing.T) {
	type received struct {
		mu     sync.Mutex
		bodies []string
	}
	serve := func(decode func([]byte) ([]byte, error)) (*httptest.Server, *received) {
		rec := &received{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			plain, err := decode(b)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rec.mu.Lock()
			rec.bodies = append(rec.bodies, string(plain))
			rec.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		return srv, rec
	}
	prom, promRec := serve(func(b []byte) ([]byte, error) { return snappy.Decode(nil, b) })
	influx, influxRec := serve(func(b []byte) ([]byte, error) {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	})
	agent := testagent.Start(t, nil, interfacesMIB(true, true), nil)
	dataDir := filepath.Join(t.TempDir(), "data")
	_, file, _, _ := runtime.Caller(0)
	cfg, err := config.Parse(strings.NewReader(fmt.Sprintf(`
global: { data_dir: %s, stats_interval: 1s }
sinks:
  - { id: prom, type: prometheus, url: "%s/api/v1/write", flush_interval: 10ms }
  - { id: influx, type: influxdb, url: "%s", database: snmp, flush_interval: 10ms,
      tags: [device, { host: sysName }, labels, index] }
devices:
  - { id: sw, address: 127.0.0.1, port: %d, poll_interval: 1s, snmp: { version: 2c, community: %s } }
`, dataDir, prom.URL, influx.URL, agent.Port, testagent.Community)), filepath.Join(filepath.Dir(file), "..", "..", "etc"))
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
	p, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}

	all := func(rec *received) string {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return strings.Join(rec.bodies, "\n")
	}
	lp := all(influxRec)
	for _, want := range []string{
		"system,device=sw,host=sw uptime=1000i,sysUpTime=1000i ",
		"interfaces,device=sw,host=sw,ifAlias=",
		",ifDescr=TenGigE0/1,ifName=",
		",index=1 ifInOctets_rate=", // second poll: rates
		"ifOperStatus=1i",
	} {
		if !strings.Contains(lp, want) {
			t.Errorf("influxdb: %q not found in:\n%s", want, lp)
		}
	}
	pb := all(promRec)
	for _, want := range []string{"snmp_uptime", "snmp_ifInOctets_rate", "ifDescr", "TenGigE0/1", "device", "index"} {
		if !strings.Contains(pb, want) {
			t.Errorf("prometheus: %q not found", want)
		}
	}
	logMu.Lock()
	text := logs.String()
	logMu.Unlock()
	if !strings.Contains(text, `msg="sink stats" sink=influx state=up`) || !strings.Contains(text, `msg="sink stats" sink=prom state=up`) {
		t.Errorf("sink stats missing:\n%s", text)
	}
	if strings.Contains(text, "level=WARN") {
		t.Errorf("warnings:\n%s", text)
	}
}
