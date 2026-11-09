package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ifCap is a capability with discovery data and a labelled table.
const ifCap = `
discovery:
  scalars: { sysName: 1.3.6.1.2.1.1.5.0 }
  columns: { ifDescr: 1.3.6.1.2.1.2.2.1.2, ifAlias: 1.3.6.1.2.1.31.1.1.1.18, ifSpeed: 1.3.6.1.2.1.2.2.1.5 }
scalars: [{ name: uptime, oid: 1.3.6.1.2.1.1.3.0 }]
tables:
  - name: interfaces
    label: ifDescr
    labels: [ifAlias]
    columns:
      - { name: ifInOctets, oid: 1.3.6.1.2.1.2.2.1.10, modes: [rate, volume] }
      - { name: ifSpeed, oid: 1.3.6.1.2.1.2.2.1.5 }
`

const storageCap = `
discovery:
  columns: { hrStorageDescr: 1.3.6.1.2.1.25.2.3.1.3 }
tables:
  - name: storage
    label: hrStorageDescr
    columns: [{ name: used, oid: 1.3.6.1.2.1.25.2.3.1.6 }]
`

func parseSinks(t *testing.T, sinks string) (*Config, error) {
	t.Helper()
	return parseWith(t, "sinks:\n"+sinks, map[string]string{"if.yaml": ifCap, "storage.yaml": storageCap})
}

func TestSinkDefaults(t *testing.T) {
	c, err := parseSinks(t, `
  - { id: prom, type: prometheus, url: "http://prom:9090/api/v1/write" }
  - { id: influx, type: influxdb, url: "https://influx:8181", database: snmp, disk_buffer: 500MiB }
  - { id: none, type: influxdb, url: "http://i", database: d, disk_buffer: 0, prefix: snmp_ }
  - { id: null-buffer, type: influxdb, url: "http://i", database: d, disk_buffer: null }
`)
	if err != nil {
		t.Fatal(err)
	}
	p, i := c.Sinks[0], c.Sinks[1]
	if *p.Prefix != "snmp_" || *i.Prefix != "" || *c.Sinks[2].Prefix != "snmp_" {
		t.Errorf("prefixes = %q %q %q", *p.Prefix, *i.Prefix, *c.Sinks[2].Prefix)
	}
	if p.Timeout != 10*time.Second || p.BatchSize != 5000 || p.FlushInterval != time.Second {
		t.Errorf("defaults = %v %d %v", p.Timeout, p.BatchSize, p.FlushInterval)
	}
	for _, tc := range []struct {
		sink Sink
		want int64
	}{{p, 1_000_000_000}, {i, 500 << 20}, {c.Sinks[2], 0}, {c.Sinks[3], 0}} {
		if tc.sink.DiskBuffer.Bytes != tc.want {
			t.Errorf("%s: disk_buffer = %d, want %d", tc.sink.ID, tc.sink.DiskBuffer.Bytes, tc.want)
		}
	}
	var tags []string
	for _, tg := range p.ResolvedTags {
		tags = append(tags, tg.Name)
	}
	if strings.Join(tags, ",") != "device,index,labels" {
		t.Errorf("default tags = %v", tags)
	}
}

func TestSinkTags(t *testing.T) {
	c, err := parseSinks(t, `
  - id: influx
    type: influxdb
    url: http://i:8181
    database: snmp
    tags: [device, { host: sysName }, { speed: ifSpeed }, { descr: hrStorageDescr }, labels, address, table, capability, index]
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Tag{
		{Name: "device", Source: "device", Kind: KindDevice},
		{Name: "host", Source: "sysName", Kind: KindScalar},
		{Name: "speed", Source: "ifSpeed", Kind: KindColumn, Capabilities: []string{"if"}},
		{Name: "descr", Source: "hrStorageDescr", Kind: KindColumn, Capabilities: []string{"storage"}},
		{Name: "labels", Source: "labels", Kind: KindLabels},
		{Name: "address", Source: "address", Kind: KindAddress},
		{Name: "table", Source: "table", Kind: KindTable},
		{Name: "capability", Source: "capability", Kind: KindCapability},
		{Name: "index", Source: "index", Kind: KindIndex},
	}
	got := c.Sinks[0].ResolvedTags
	if len(got) != len(want) {
		t.Fatalf("tags = %+v", got)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Kind != want[i].Kind || strings.Join(got[i].Capabilities, ",") != strings.Join(want[i].Capabilities, ",") {
			t.Errorf("tag %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSinkKeys(t *testing.T) {
	c, err := parseSinks(t, `
  - id: p
    type: prometheus
    url: http://p/api/v1/write
    keys: { include: ['^if'], exclude: ['_volume$'] }
`)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sinks[0]
	for key, want := range map[string]bool{"ifInOctets_rate": true, "ifInOctets_volume": false, "uptime": false, "ifSpeed": true} {
		if s.Sends(key) != want {
			t.Errorf("Sends(%q) = %v", key, !want)
		}
	}
	if SampleKey("x", ModeRaw) != "x" || SampleKey("x", ModeRate) != "x_rate" || SampleKey("x", ModeVolume) != "x_volume" {
		t.Error("SampleKey")
	}
}

func TestSinkErrors(t *testing.T) {
	prom := `type: prometheus, url: "http://p/api/v1/write"`
	influx := `type: influxdb, url: "http://i:8181", database: snmp`
	for _, tc := range []struct{ sinks, want string }{
		{`[{ type: prometheus, url: "http://p" }]`, "sinks[0]: id is required"},
		{`[{ id: "a b", ` + prom + ` }]`, "id may only contain"},
		{`[{ id: a, type: "null" }]`, `type "null" was removed`},
		{`[{ id: a, type: kafka, url: "http://x" }]`, `type "kafka": must be influxdb or prometheus`},
		{`[{ id: a, type: prometheus }]`, "url is required"},
		{`[{ id: a, type: prometheus, url: "p:9090" }]`, "must be an http:// or https:// URL"},
		{`[{ id: a, type: influxdb, url: "http://i" }]`, "database is required"},
		{`[{ id: a, type: prometheus, url: "https://u:secret@p/w" }]`, "not in the URL"},
		{`[{ id: a, ` + prom + `, database: x }]`, "database is only used by influxdb"},
		{`[{ id: a, ` + prom + `, batch_size: -1 }]`, "batch_size must be >= 1"},
		{`[{ id: a, ` + prom + `, disk_buffer: 1PB }]`, `unknown unit "PB"`},
		{`[{ id: a, ` + prom + `, disk_buffer: lots }]`, "invalid size"},
		{`[{ id: a, ` + prom + `, token: t, username: u }]`, "token and username/password are exclusive"},
		{`[{ id: a, ` + prom + `, password: p }]`, "password requires username"},
		{`[{ id: a, ` + prom + `, client_cert: c.pem }]`, "client_cert and client_key go together"},
		{`[{ id: a, ` + prom + `, headers: { authorization: x } }]`, "set Authorization with token"},
		{`[{ id: a, ` + prom + `, prefix: "1x" }]`, "prefix"},
		{`[{ id: a, ` + prom + `, keys: { include: ["("] } }]`, "keys.include"},
		{`[{ id: a, ` + prom + `, tags: [nope] }]`, `unknown source "nope"`},
		{`[{ id: a, ` + prom + `, tags: [device, { device: address }] }]`, `duplicate tag "device"`},
		{`[{ id: a, ` + prom + `, tags: [{ my-host: sysName }] }]`, "not a valid Prometheus label name"},
		{`[{ id: a, ` + prom + `, tags: [{ __x: sysName }] }]`, "not a valid Prometheus label name"},
		{`[{ id: a, ` + prom + `, tags: [{ l: labels }] }]`, "labels cannot be renamed"},
		{`[{ id: a, ` + prom + `, tags: device }]`, "tags must be a list"},
		{`[{ id: a, ` + influx + `, tags: [{ time: sysName }] }]`, `"time" is reserved`},
		{`[{ id: a, ` + influx + `, tags: [ifSpeed] }]`, `tag "ifSpeed" is also a field of measurement "interfaces"`},
		{`[{ id: a, ` + prom + `, bogus: 1 }]`, "field bogus not found"},
	} {
		_, err := parseSinks(t, "  - "+strings.TrimPrefix(strings.TrimSuffix(tc.sinks, "]"), "[")+"\n")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\n  err = %v, want containing %q", tc.sinks, err, tc.want)
		}
	}
	// A tag that is a field elsewhere only: no conflict once excluded.
	if _, err := parseSinks(t, `  - { id: a, type: influxdb, url: "http://i", database: d, tags: [ifSpeed], keys: { exclude: ['^ifSpeed$'] } }`+"\n"); err != nil {
		t.Errorf("excluded key: %v", err)
	}
}

func TestPrometheusNameCollision(t *testing.T) {
	both := map[string]string{"a.yaml": `tables: [{ name: ta, columns: [{ name: used, oid: 1.3.6.1.2 }] }]`,
		"b.yaml": `tables: [{ name: tb, columns: [{ name: used, oid: 1.3.6.1.3 }] }]`}
	_, err := parseWith(t, `sinks: [{ id: p, type: prometheus, url: "http://p/w" }]`, both)
	if err == nil || !strings.Contains(err.Error(), `metric snmp_used is emitted by table "ta" of capability "a" and table "tb" of capability "b"`) {
		t.Errorf("err = %v", err)
	}
	// InfluxDB measurements are the tables: no collision.
	if _, err := parseWith(t, `sinks: [{ id: i, type: influxdb, url: "http://i", database: d }]`, both); err != nil {
		t.Error(err)
	}
}

func TestDeviceSinks(t *testing.T) {
	c, err := parse(t, `
sinks:
  - { id: a, type: prometheus, url: "http://p/w" }
  - { id: b, type: prometheus, url: "http://q/w" }
devices:
  - { id: all, address: 192.0.2.1, snmp: { version: 2c, community: c } }
  - { id: one, address: 192.0.2.2, snmp: { version: 2c, community: c }, sinks: [b] }
  - { id: none, address: 192.0.2.3, snmp: { version: 2c, community: c }, sinks: [] }
`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range c.DeviceSpecs() {
		got = append(got, s.ID+"="+strings.Join(s.Sinks, "+"))
	}
	if strings.Join(got, " ") != "all=a+b one=b none=" {
		t.Errorf("sinks = %v", got)
	}
	if _, err := parse(t, `
sinks: [{ id: a, type: prometheus, url: "http://p/w" }]
devices: [{ id: d, address: 192.0.2.1, snmp: { version: 2c, community: c }, sinks: [a, a] }]`); err == nil ||
		!strings.Contains(err.Error(), `"a" is listed twice`) {
		t.Errorf("err = %v", err)
	}
	if _, err := parse(t, `devices: [{ id: sinks, address: 192.0.2.1, snmp: { version: 2c, community: c } }]`); err == nil ||
		!strings.Contains(err.Error(), `id "sinks" is reserved`) {
		t.Errorf("err = %v", err)
	}
}

func TestParseByteSize(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "1000": 1000, "1GB": 1e9, "1 gb": 1e9, "1.5MB": 1_500_000,
		"2GiB": 2 << 30, "10KiB": 10240, "1TB": 1e12, "512B": 512} {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "1XB", "GB", "1e9", "99999999TB"} {
		if _, err := ParseByteSize(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}

func TestSinkEqual(t *testing.T) {
	doc := `
  - { id: a, type: influxdb, url: "http://i", database: d, token: %s, tags: [device, sysName] }
`
	c1, _ := parseSinks(t, strings.Replace(doc, "%s", "t1", 1))
	c2, _ := parseSinks(t, "\n\n"+strings.Replace(doc, "%s", "t1", 1)) // moved: same
	c3, _ := parseSinks(t, strings.Replace(doc, "%s", "t2", 1))
	if !c1.Sinks[0].Equal(&c2.Sinks[0]) {
		t.Error("same sink must be equal")
	}
	if c1.Sinks[0].Equal(&c3.Sinks[0]) {
		t.Error("another token must differ")
	}
}

func TestSealSinkSecrets(t *testing.T) {
	path := writeConfig(t, `
global: { data_dir: `+t.TempDir()+` }
sinks:
  - { id: i, type: influxdb, url: "http://i", database: d, token: influx-token }
  - { id: p, type: prometheus, url: "http://p/w", username: u, password: prom-pass }
`, nil)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Seal()
	if err != nil || res.Encrypted != 2 {
		t.Fatalf("seal: %+v %v", res, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "influx-token") || strings.Contains(string(data), "prom-pass") {
		t.Errorf("secrets left in clear text:\n%s", data)
	}
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sinks[0].Token.Reveal() != "influx-token" || c.Sinks[1].Password.Reveal() != "prom-pass" {
		t.Error("secrets not decrypted")
	}
}
