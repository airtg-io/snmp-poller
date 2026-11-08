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
	if err := store.Clean(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Clean left %d entries", len(entries))
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
