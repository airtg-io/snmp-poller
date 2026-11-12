package state

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/airtg-io/snmp-poller/internal/snmp"
)

func TestDelta(t *testing.T) {
	t0 := time.Unix(1000, 0)
	t1 := t0.Add(10 * time.Second)
	for _, tc := range []struct {
		name   string
		a, b   snmp.Value
		volume float64
		ok     bool
	}{
		{"counter64", snmp.Value{Kind: snmp.KindCounter64, Uint: 1000}, snmp.Value{Kind: snmp.KindCounter64, Uint: 6000}, 5000, true},
		{"counter64 reset", snmp.Value{Kind: snmp.KindCounter64, Uint: 6000}, snmp.Value{Kind: snmp.KindCounter64, Uint: 10}, 0, false},
		{"counter32 wrap", snmp.Value{Kind: snmp.KindCounter32, Uint: math.MaxUint32 - 99}, snmp.Value{Kind: snmp.KindCounter32, Uint: 100}, 200, true},
		{"gauge down", snmp.Value{Kind: snmp.KindUnsigned, Uint: 50}, snmp.Value{Kind: snmp.KindUnsigned, Uint: 20}, -30, true},
		{"integer", snmp.Value{Kind: snmp.KindInteger, Int: -5}, snmp.Value{Kind: snmp.KindInteger, Int: 5}, 10, true},
		{"float", snmp.Value{Kind: snmp.KindFloat, Float: 1.5}, snmp.Value{Kind: snmp.KindFloat, Float: 4}, 2.5, true},
		{"kind change", snmp.Value{Kind: snmp.KindCounter32, Uint: 1}, snmp.Value{Kind: snmp.KindCounter64, Uint: 2}, 0, false},
		{"string", snmp.Value{Kind: snmp.KindString, Str: "a"}, snmp.Value{Kind: snmp.KindString, Str: "b"}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			d, _ := store.Load("dev")
			if _, _, ok := d.Delta("k", tc.a, t0); ok {
				t.Fatal("first sample must not yield a delta")
			}
			if err := d.Save(); err != nil {
				t.Fatal(err)
			}
			d, err = store.Load("dev")
			if err != nil {
				t.Fatal(err)
			}
			vol, secs, ok := d.Delta("k", tc.b, t1)
			if ok != tc.ok || (ok && (vol != tc.volume || secs != 10)) {
				t.Errorf("Delta = %v, %v, %v; want %v, 10, %v", vol, secs, ok, tc.volume, tc.ok)
			}
		})
	}
}

func TestSaveDropsUnseenKeysAndResets(t *testing.T) {
	dir := t.TempDir()
	store, _ := New(dir)
	now := time.Now()
	v := snmp.Value{Kind: snmp.KindCounter64, Uint: 1}

	d, _ := store.Load("dev")
	d.Delta("a", v, now)
	d.Delta("b", v, now)
	d.Save()

	d, _ = store.Load("dev")
	d.Delta("a", v, now.Add(time.Second))
	d.Save()

	d, _ = store.Load("dev")
	if _, ok := d.prev["b"]; ok {
		t.Error("key not seen in last poll must be dropped")
	}
	if _, ok := d.prev["a"]; !ok {
		t.Error("key a lost")
	}

	if err := store.ResetDevice("dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dev")); !os.IsNotExist(err) {
		t.Error("ResetDevice must remove the device directory")
	}

	store.SaveDiscovery("other", map[string]string{"x": "y"})
	os.WriteFile(filepath.Join(dir, "key.dat"), []byte("k"), 0o600)
	buffer := filepath.Join(dir, "sinks", "influx", "00000000000000000001.seg")
	os.MkdirAll(filepath.Dir(buffer), 0o755)
	os.WriteFile(buffer, []byte("data"), 0o644)
	if err := store.Clean(); err != nil {
		t.Fatal(err)
	}
	// Device directories go, files (the credentials key) and the disk
	// buffers of the sinks stay.
	if entries, _ := os.ReadDir(dir); len(entries) != 2 || entries[0].Name() != "key.dat" || entries[1].Name() != "sinks" {
		t.Errorf("Clean left %v, want key.dat and sinks", entries)
	}
	if _, err := os.Stat(buffer); err != nil {
		t.Errorf("disk buffer removed: %v", err)
	}
}

func TestCorruptStateStartsOver(t *testing.T) {
	dir := t.TempDir()
	store, _ := New(dir)
	os.MkdirAll(filepath.Join(dir, "dev"), 0o755)
	os.WriteFile(filepath.Join(dir, "dev", stateFile), []byte("{not json"), 0o644)
	d, err := store.Load("dev")
	if err == nil {
		t.Error("expected an error for corrupt state")
	}
	if d == nil || len(d.prev) != 0 {
		t.Error("corrupt state must yield an empty, usable state")
	}
}

// TestAgentRestart: no delta at the poll that sees the agent restarted nor
// at the next one, normal deltas after.
func TestAgentRestart(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const day = 8_640_000 // TimeTicks
	t0 := time.Unix(1000, 0)
	type poll struct {
		uptime  uint64 // 0: not read
		counter uint64
		restart bool // AgentUptime's answer
		delta   bool // a delta is computed
	}
	for i, p := range []poll{
		{uptime: day, counter: 100},                     // first poll: nothing to compare
		{uptime: day + 1000, counter: 200, delta: true}, // normal
		{uptime: 500, counter: 0, restart: true},        // restarted: previous value is pre-restart
		{uptime: 1500, counter: 742_000},                // first read after start may be wrong
		{uptime: 2500, counter: 742_100, delta: true},   // back to normal
		{counter: 742_200, delta: true},                 // uptime not read: deltas go on
		{uptime: 3500, counter: 742_300, delta: true},   // still normal
	} {
		d, err := store.Load("dev")
		if err != nil {
			t.Fatal(err)
		}
		if p.uptime != 0 {
			if got := d.AgentUptime(p.uptime, time.Minute); got != p.restart {
				t.Errorf("poll %d: restart = %v, want %v", i, got, p.restart)
			}
		}
		_, _, ok := d.Delta("c", snmp.Value{Kind: snmp.KindCounter64, Uint: p.counter}, t0.Add(time.Duration(i)*10*time.Second))
		if ok != p.delta {
			t.Errorf("poll %d: delta computed = %v, want %v", i, ok, p.delta)
		}
		if err := d.Save(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAgentJustStarted: without a previous uptime (first poll, or after a
// rediscovery), an agent up for less than one poll interval counts as just
// started; one up longer does not.
func TestAgentJustStarted(t *testing.T) {
	for _, tc := range []struct {
		ticks   uint64
		restart bool
	}{{100, true}, {5999, true}, {6000, false}, {8_640_000, false}} {
		store, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		d, _ := store.Load("dev")
		if got := d.AgentUptime(tc.ticks, time.Minute); got != tc.restart {
			t.Errorf("uptime %d ticks, interval 1m: restart = %v, want %v", tc.ticks, got, tc.restart)
		}
	}
}

// TestStateFileBeforeUptime: a state file written before 0.4 (values only)
// is read as such.
func TestStateFileBeforeUptime(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.DeviceDir("dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := `{"c":{"k":"counter64","u":100,"t":1000000000000}}`
	if err := os.WriteFile(filepath.Join(store.DeviceDir("dev"), "state.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := store.Load("dev")
	if err != nil {
		t.Fatal(err)
	}
	vol, _, ok := d.Delta("c", snmp.Value{Kind: snmp.KindCounter64, Uint: 150}, time.Unix(1010, 0))
	if !ok || vol != 50 {
		t.Errorf("delta from an old state file = %v, %v", vol, ok)
	}
}
