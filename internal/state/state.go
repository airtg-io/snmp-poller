// Package state persists, under <data_dir>/<device_id>/, the discovery
// result of every device and the previous value of every rate/volume metric,
// so memory usage does not grow with the number of devices, rows or polled
// OIDs. A device's data is only held in memory while that device is being
// polled.
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

	"github.com/airtg-io/snmp-poller/internal/config"
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

// Clean removes every device directory. Called on startup. Files, such as
// the credentials key (config.KeyFile), and the disk buffers of the sinks
// (config.SinksDir) are kept.
func (s *Store) Clean() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() && e.Name() != config.SinksDir {
			errs = append(errs, os.RemoveAll(filepath.Join(s.dir, e.Name())))
		}
	}
	return errors.Join(errs...)
}

// ResetDevice wipes a device's directory. Called on every (re)discovery:
// row indexes may have changed, so previous values cannot be trusted.
func (s *Store) ResetDevice(id string) error {
	return os.RemoveAll(s.DeviceDir(id))
}

// SaveDiscovery writes the device's discovery result as JSON. It is the
// device's discovery cache: read back by every poll until the next
// discovery, and readable by operators.
func (s *Store) SaveDiscovery(id string, v any) error {
	return s.writeJSON(id, discoveryFile, v)
}

// LoadDiscovery reads the discovery result saved by SaveDiscovery into v.
func (s *Store) LoadDiscovery(id string, v any) error {
	data, err := os.ReadFile(filepath.Join(s.DeviceDir(id), discoveryFile))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("corrupt %s: %w", discoveryFile, err)
	}
	return nil
}

// entry is one previous value. Short JSON keys keep files small.
type entry struct {
	Kind  snmp.Kind `json:"k"`
	Uint  uint64    `json:"u,omitempty"`
	Int   int64     `json:"i,omitempty"`
	Float float64   `json:"f,omitempty"`
	Time  int64     `json:"t"`
}

// file is the content of the state file.
type file struct {
	// Uptime is the agent's sysUpTime (TimeTicks) read by that poll.
	Uptime *uint64 `json:"uptime,omitempty"`
	// Restarted reports that the agent had restarted before that poll.
	Restarted bool             `json:"restarted,omitempty"`
	Values    map[string]entry `json:"values"`
}

// Device is the state of one device during one poll. Obtain it with Load,
// call AgentUptime when the poll read it, then Delta for every rate/volume
// value, then Save.
type Device struct {
	store *Store
	id    string
	prev  map[string]entry
	next  map[string]entry

	prevUptime    *uint64
	prevRestarted bool
	uptime        *uint64
	restarted     bool
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
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return d, fmt.Errorf("corrupt %s, starting over: %w", stateFile, err)
	}
	if f.Values == nil {
		// Before 0.4 the file held the values only: read it as such.
		if err := json.Unmarshal(data, &d.prev); err != nil {
			d.prev = map[string]entry{}
			return d, fmt.Errorf("corrupt %s, starting over: %w", stateFile, err)
		}
		return d, nil
	}
	d.prev, d.prevUptime, d.prevRestarted = f.Values, f.Uptime, f.Restarted
	return d, nil
}

// AgentUptime records the agent's uptime read by this poll (sysUpTime, in
// hundredths of a second), before any Delta, and reports whether the agent
// restarted since the previous poll: its uptime went backwards or, without
// a previous uptime, is shorter than interval (the agent started since the
// previous poll could have run).
//
// Deltas are not computed at a restart poll, whose previous values predate
// the restart, nor at the poll after it: some agents report wrong counters
// on their first read after starting (net-snmp gives 0 for ifInUcastPkts),
// which would make the first rate a huge spike.
func (d *Device) AgentUptime(ticks uint64, interval time.Duration) (restarted bool) {
	d.uptime = &ticks
	if d.prevUptime != nil {
		d.restarted = ticks < *d.prevUptime
	} else {
		d.restarted = time.Duration(ticks)*10*time.Millisecond < interval
	}
	return d.restarted
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
	if d.restarted || d.prevRestarted {
		return 0, 0, false // see AgentUptime
	}
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

// Save writes the values and agent uptime recorded during this poll,
// replacing the previous file. Keys not seen during this poll are dropped.
func (d *Device) Save() error {
	if len(d.next) == 0 && len(d.prev) == 0 && d.uptime == nil && d.prevUptime == nil {
		return nil
	}
	uptime := d.uptime
	if uptime == nil {
		uptime = d.prevUptime // not read this time: the last one known is still a lower bound
	}
	return d.store.writeJSON(d.id, stateFile, file{Uptime: uptime, Restarted: d.restarted, Values: d.next})
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
