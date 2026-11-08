// Package state persists the previous value of every rate/volume metric on
// disk, under <data_dir>/<device_id>/, so memory usage does not grow with the
// number of polled OIDs. A device's state is only held in memory while that
// device is being polled.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/airtg-io/snmp-poller/internal/snmp"
)

const (
	stateFile     = "state.json"
	discoveryFile = "discovery.json"
)

// Store is the on-disk data directory.
type Store struct {
	dir string
}

// New returns a store rooted at dir. The directory is created if needed.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the root directory.
func (s *Store) Dir() string { return s.dir }

// DeviceDir returns the directory holding a device's files.
func (s *Store) DeviceDir(id string) string { return filepath.Join(s.dir, id) }

// Clean removes every device directory. Called on startup.
func (s *Store) Clean() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		errs = append(errs, os.RemoveAll(filepath.Join(s.dir, e.Name())))
	}
	return errors.Join(errs...)
}

// ResetDevice wipes a device's directory. Called on every (re)discovery:
// row indexes may have changed, so previous values cannot be trusted.
func (s *Store) ResetDevice(id string) error {
	return os.RemoveAll(s.DeviceDir(id))
}

// SaveDiscovery writes the device's discovery result as JSON, for operators.
func (s *Store) SaveDiscovery(id string, v any) error {
	return s.writeJSON(id, discoveryFile, v)
}

// entry is one previous value. Short JSON keys keep files small.
type entry struct {
	Kind  snmp.Kind `json:"k"`
	Uint  uint64    `json:"u,omitempty"`
	Int   int64     `json:"i,omitempty"`
	Float float64   `json:"f,omitempty"`
	Time  int64     `json:"t"`
}

// Device is the state of one device during one poll. Obtain it with Load,
// call Delta for every rate/volume value, then Save.
type Device struct {
	store *Store
	id    string
	prev  map[string]entry
	next  map[string]entry
}

// Load reads a device's previous values. A missing or unreadable file
// yields an empty state (the next poll simply has no deltas).
func (s *Store) Load(id string) (*Device, error) {
	d := &Device{store: s, id: id, prev: map[string]entry{}, next: map[string]entry{}}
	data, err := os.ReadFile(filepath.Join(s.DeviceDir(id), stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(data, &d.prev); err != nil {
		d.prev = map[string]entry{}
		return d, fmt.Errorf("corrupt %s, starting over: %w", stateFile, err)
	}
	return d, nil
}

// Delta records v as the current value of key and returns the difference
// with the previous value (volume) and the elapsed seconds. ok is false when
// no meaningful delta exists: first sample, type change, non-numeric value,
// clock going backwards, or a Counter64 that went backwards (agent reset).
// Counter32 wraps are handled.
func (d *Device) Delta(key string, v snmp.Value, t time.Time) (volume, seconds float64, ok bool) {
	if !v.Numeric() {
		return 0, 0, false
	}
	cur := entry{Kind: v.Kind, Uint: v.Uint, Int: v.Int, Float: v.Float, Time: t.UnixNano()}
	d.next[key] = cur
	p, found := d.prev[key]
	if !found || p.Kind != cur.Kind || cur.Time <= p.Time {
		return 0, 0, false
	}
	seconds = float64(cur.Time-p.Time) / float64(time.Second)
	switch cur.Kind {
	case snmp.KindCounter32:
		if cur.Uint >= p.Uint {
			volume = float64(cur.Uint - p.Uint)
		} else {
			volume = float64(cur.Uint + (math.MaxUint32 + 1) - p.Uint)
		}
	case snmp.KindCounter64:
		if cur.Uint < p.Uint {
			return 0, 0, false
		}
		volume = float64(cur.Uint - p.Uint)
	case snmp.KindUnsigned:
		volume = float64(cur.Uint) - float64(p.Uint)
	case snmp.KindInteger:
		volume = float64(cur.Int - p.Int)
	case snmp.KindFloat:
		volume = cur.Float - p.Float
	default:
		return 0, 0, false
	}
	return volume, seconds, true
}

// Len returns the number of values recorded during this poll.
func (d *Device) Len() int { return len(d.next) }

// Save writes the values recorded during this poll, replacing the previous
// file. Keys not seen during this poll are dropped.
func (d *Device) Save() error {
	if len(d.next) == 0 && len(d.prev) == 0 {
		return nil
	}
	return d.store.writeJSON(d.id, stateFile, d.next)
}

// writeJSON atomically replaces <device dir>/<name>.
func (s *Store) writeJSON(id, name string, v any) error {
	dir := s.DeviceDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
