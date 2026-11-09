package poller

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/testagent"
	"github.com/airtg-io/snmp-poller/internal/testconf"
)

// reloadRig runs a poller on a configuration file that the test rewrites.
type reloadRig struct {
	t       *testing.T
	dir     string // main file, capabilities.d, conf.d, data
	path    string
	dataDir string
	ports   map[string]uint16 // device id -> agent port
	out     *capture
	p       *Poller
	logMu   sync.Mutex
	logs    bytes.Buffer
	logConf []config.Logging
	cancel  context.CancelFunc
	done    chan error
}

// lockedWriter serializes writes to the log buffer of the rig.
type lockedWriter struct{ r *reloadRig }

func (w lockedWriter) Write(b []byte) (int, error) {
	w.r.logMu.Lock()
	defer w.r.logMu.Unlock()
	return w.r.logs.Write(b)
}

func newReloadRig(t *testing.T, ids ...string) *reloadRig {
	r := &reloadRig{t: t, dir: testconf.Write(t, basicCaps), ports: map[string]uint16{}, out: &capture{}}
	r.path = filepath.Join(r.dir, "snmp-poller.yaml")
	r.dataDir = filepath.Join(r.dir, "data")
	for _, id := range ids {
		r.ports[id] = testagent.Start(t, nil, testagent.NewMIB(sysMIB(id)), nil).Port
	}
	return r
}

// device returns the YAML of one device, polled every second.
func (r *reloadRig) device(id string, extra string) string {
	return fmt.Sprintf("  - { id: %s, address: 127.0.0.1, port: %d, poll_interval: 1s, timeout: 300ms, retries: 0, %s snmp: { version: 2c, community: %s } }\n",
		id, r.ports[id], extra, testagent.Community)
}

// write writes the main file: global settings plus the given devices.
func (r *reloadRig) write(global string, devices ...string) {
	r.t.Helper()
	doc := fmt.Sprintf("global: { data_dir: %s, stats_interval: 1h%s }\noutputs: [{ name: cap, type: \"null\" }]\ndevices:\n%s",
		r.dataDir, global, strings.Join(devices, ""))
	r.writeFile("snmp-poller.yaml", doc)
}

func (r *reloadRig) writeFile(name, doc string) {
	r.t.Helper()
	path := filepath.Join(r.dir, name)
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *reloadRig) start() {
	r.t.Helper()
	cfg, err := config.Load(r.path)
	if err != nil {
		r.t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(lockedWriter{r}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.p, err = New(cfg, log, map[string]output.Output{"cap": r.out})
	if err != nil {
		r.t.Fatal(err)
	}
	r.p.watchEvery = 50 * time.Millisecond
	r.p.EnableReload(config.Load, func(l config.Logging) error {
		r.logMu.Lock()
		defer r.logMu.Unlock()
		r.logConf = append(r.logConf, l)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan error, 1)
	go func() { r.done <- r.p.Run(ctx) }()
	r.t.Cleanup(r.stop)
}

func (r *reloadRig) stop() {
	if r.cancel != nil {
		r.cancel()
		if err := <-r.done; err != nil {
			r.t.Error(err)
		}
		r.cancel = nil
	}
}

func (r *reloadRig) logText() string {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	return r.logs.String()
}

// waitFor fails the test when cond is still false after timeout.
func (r *reloadRig) waitFor(what string, timeout time.Duration, cond func() bool) {
	r.t.Helper()
	for end := time.Now().Add(timeout); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			r.t.Fatalf("timeout waiting for %s; logs:\n%s", what, r.logText())
		}
	}
}

// reloads counts the "configuration reloaded" log lines.
func (r *reloadRig) reloads() int { return strings.Count(r.logText(), `msg="configuration reloaded"`) }

func (r *reloadRig) failures() int {
	return strings.Count(r.logText(), `msg="configuration reload failed, the previous configuration stays in force"`)
}

// discovered returns the time of the device's last discovery, from its
// on-disk cache (zero when there is none).
func (r *reloadRig) discovered(id string) time.Time {
	var d Discovery
	if err := r.p.store.LoadDiscovery(id, &d); err != nil {
		return time.Time{}
	}
	return d.Time
}

// TestHotReload: a file change is applied without restart. Devices that
// did not change keep their discovery cycle; new ones are polled, removed
// ones stop; an invalid configuration is reported and changes nothing.
func TestHotReload(t *testing.T) {
	r := newReloadRig(t, "a", "b", "c")
	r.write("", r.device("a", ""), r.device("b", ""))
	r.start()
	r.waitFor("first polls", 3*time.Second, func() bool { return r.out.count("a") >= 1 && r.out.count("b") >= 1 })
	discA := r.discovered("a")

	// Add c, remove b, change a's settings (not what its discovery depends
	// on), in two files: the include directory is watched too.
	r.write("", r.device("a", "max_oids_per_request: 20, trace: true,"))
	r.writeFile("conf.d/c.yaml", "devices:\n"+r.device("c", ""))
	r.waitFor("reload", 3*time.Second, func() bool { return r.reloads() == 1 })
	if !strings.Contains(r.logText(), "devices=2 added=1 removed=1 changed=1 rediscovered=0") {
		t.Errorf("reload summary wrong:\n%s", r.logText())
	}
	r.waitFor("c polled", 3*time.Second, func() bool { return r.out.count("c") >= 1 })
	afterReload := r.out.count("b")
	nA := r.out.count("a")
	r.waitFor("a polled again", 3*time.Second, func() bool { return r.out.count("a") >= nA+2 })
	if got := r.discovered("a"); !got.Equal(discA) {
		t.Errorf("a rediscovered at %v (first discovery %v): its discovery did not depend on the change", got, discA)
	}
	if n := r.out.count("b"); n > afterReload {
		t.Errorf("b polled %d times after its removal", n-afterReload)
	}
	if _, err := os.Stat(r.p.store.DeviceDir("b")); !os.IsNotExist(err) {
		t.Errorf("data of removed device b kept: %v", err)
	}
	if !strings.Contains(r.logText(), "device=a") || !strings.Contains(r.logText(), `msg="poll done" device=a`) {
		t.Error("trace: true on a not applied")
	}

	// An invalid configuration: logged once, nothing changes.
	r.writeFile("conf.d/c.yaml", "devices:\n  - { id: d, address: 127.0.0.1 }\n")
	r.waitFor("reload failure", 3*time.Second, func() bool { return r.failures() == 1 })
	if !strings.Contains(r.logText(), `conf.d/c.yaml: device \"d\": snmp is required`) {
		t.Errorf("failure does not name the error:\n%s", r.logText())
	}
	nC := r.out.count("c")
	r.waitFor("c still polled", 3*time.Second, func() bool { return r.out.count("c") > nC })
	if r.failures() != 1 || r.reloads() != 1 {
		t.Errorf("failures = %d, reloads = %d: an invalid file is reported once", r.failures(), r.reloads())
	}

	// What discovery depends on changed (here: the capabilities of a): a is
	// discovered again, c is not.
	discC := r.discovered("c")
	r.write("", r.device("a", "exclude: [uptime],"))
	r.writeFile("conf.d/c.yaml", "devices:\n"+r.device("c", ""))
	r.waitFor("second reload", 3*time.Second, func() bool { return r.reloads() == 2 })
	if !strings.Contains(r.logText(), "devices=2 added=0 removed=0 changed=1 rediscovered=1") {
		t.Errorf("reload summary wrong:\n%s", r.logText())
	}
	r.waitFor("a rediscovered", 3*time.Second, func() bool { return r.discovered("a").After(discA) })
	nC = r.out.count("c")
	r.waitFor("c polled", 3*time.Second, func() bool { return r.out.count("c") > nC })
	if got := r.discovered("c"); !got.Equal(discC) {
		t.Errorf("c rediscovered: %v, was %v", got, discC)
	}

	// The same capability file edited: every device using it rediscovers.
	r.writeFile("capabilities.d/uptime.yaml", testconf.Uptime+"\ndescription: edited\n")
	r.waitFor("third reload", 3*time.Second, func() bool { return r.reloads() == 3 })
	if !strings.Contains(r.logText(), "changed=1 rediscovered=1") { // c only: a excludes uptime
		t.Errorf("reload summary wrong:\n%s", r.logText())
	}

	// data_dir cannot change while running.
	r.dataDir = filepath.Join(r.dir, "other")
	r.write("", r.device("a", "exclude: [uptime],"))
	r.waitFor("data_dir refused", 3*time.Second, func() bool { return r.failures() == 2 })
	if !strings.Contains(r.logText(), "restart to apply it") {
		t.Errorf("data_dir change not explained:\n%s", r.logText())
	}
}

// With hot_reload: false, file changes wait for Reload (SIGHUP).
func TestReloadOnSignal(t *testing.T) {
	r := newReloadRig(t, "a", "b")
	r.write(", hot_reload: false, threads: 1", r.device("a", ""))
	r.start()
	r.waitFor("first poll", 3*time.Second, func() bool { return r.out.count("a") >= 1 })
	r.write(", hot_reload: false, threads: 1", r.device("a", ""), r.device("b", ""))
	time.Sleep(300 * time.Millisecond) // several checks: none must reload
	if r.reloads() != 0 || r.out.count("b") != 0 {
		t.Fatalf("reloaded without a signal:\n%s", r.logText())
	}
	r.p.Reload()
	r.waitFor("reload", 3*time.Second, func() bool { return r.reloads() == 1 })
	r.waitFor("b polled", 3*time.Second, func() bool { return r.out.count("b") >= 1 })
	if !strings.Contains(r.logText(), `reason=signal`) {
		t.Errorf("reason not logged:\n%s", r.logText())
	}
	r.p.mu.Lock()
	workers := r.p.workers
	r.p.mu.Unlock()
	if workers != 1 {
		t.Errorf("workers = %d, want threads (1)", workers)
	}
	// A signal reloads even when nothing changed; logging is applied too.
	r.p.Reload()
	r.waitFor("second reload", 3*time.Second, func() bool { return r.reloads() == 2 })
	r.logMu.Lock()
	n := len(r.logConf)
	r.logMu.Unlock()
	if n != 2 {
		t.Errorf("logging applied %d times, want 2", n)
	}
}

// counting is an output type recording its instances, for reload tests.
type counting struct {
	name   string
	mu     sync.Mutex
	writes int
	closed bool
}

var (
	countingMu   sync.Mutex
	countingOuts []*counting
)

func init() {
	output.Register("counting", func(cfg config.Output, _ *slog.Logger) (output.Output, error) {
		c := &counting{name: fmt.Sprint(cfg.Options["tag"])}
		countingMu.Lock()
		countingOuts = append(countingOuts, c)
		countingMu.Unlock()
		return c, nil
	})
}

func (c *counting) Write(context.Context, *output.Batch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("output %s written after Close", c.name)
	}
	c.writes++
	return nil
}

func (c *counting) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *counting) state() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.closed
}

// A device being polled during a reload gets its new configuration when
// the poll ends; outputs replaced meanwhile are closed only then.
func TestReloadWhilePolling(t *testing.T) {
	r := newReloadRig(t, "a", "b")
	mainDoc := func(tag, interval string) string {
		return fmt.Sprintf(`global: { data_dir: %s }
outputs: [{ name: cap, type: "null" }, { name: x, type: counting, tag: %s }]
devices:
  - { id: a, address: 127.0.0.1, port: %d, poll_interval: %s, snmp: { version: 2c, community: c } }
  - { id: b, address: 127.0.0.1, port: %d, snmp: { version: 2c, community: c } }
`, r.dataDir, tag, r.ports["a"], interval, r.ports["b"])
	}
	cfg := testconf.Parse(t, mainDoc("one", "1h"), basicCaps)
	outs, err := output.Build(cfg.Outputs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, slog.New(slog.DiscardHandler), outs)
	if err != nil {
		t.Fatal(err)
	}
	a, b := p.devices["a"], p.devices["b"]
	a.next = time.Now().Add(time.Hour)
	a.discoveredAt = time.Now()
	oldX := outs["x"].(*counting)
	p.dispatch(a) // a is being polled
	if d, _ := p.queue.pop(); d != a {
		t.Fatal("a not queued")
	}

	gen, err := p.prepare(testconf.Parse(t, mainDoc("two", "1s"), basicCaps))
	if err != nil {
		t.Fatal(err)
	}
	_, sum := p.apply(gen)
	if sum.changed != 2 || sum.rediscover != 0 {
		t.Errorf("summary = %+v, want 2 changed (new output x), none rediscovered", sum)
	}
	newX := gen.outputs["x"].out.(*counting)
	if a.pending == nil || a.spec.PollInterval != time.Hour || a.outputs[1] != oldX {
		t.Error("a changed during its poll")
	}
	if b.outputs[1] != newX {
		t.Error("idle device b not updated at once")
	}
	if _, closed := oldX.state(); closed {
		t.Fatal("output closed while a poll may still use it")
	}
	if !a.next.Before(time.Now().Add(2 * time.Second)) {
		t.Errorf("shorter interval not applied now: next poll at %v", a.next)
	}

	p.done(a)
	if a.pending != nil || a.spec.PollInterval != time.Second || a.outputs[1] != newX {
		t.Error("pending configuration not applied when the poll ended")
	}
	if a.discoveredAt.IsZero() {
		t.Error("a forgot its discovery: nothing it depends on changed")
	}
	if _, closed := oldX.state(); !closed {
		t.Error("replaced output not closed after the last poll using it")
	}
	if _, closed := newX.state(); closed {
		t.Error("new output closed")
	}

	// Removing a device being polled: its data goes when the poll ends.
	p.dispatch(b)
	p.queue.pop()
	os.MkdirAll(p.store.DeviceDir("b"), 0o755)
	gen, err = p.prepare(testconf.Parse(t, strings.Replace(mainDoc("two", "1s"),
		fmt.Sprintf("  - { id: b, address: 127.0.0.1, port: %d, snmp: { version: 2c, community: c } }\n", r.ports["b"]), "", 1), basicCaps))
	if err != nil {
		t.Fatal(err)
	}
	if _, sum := p.apply(gen); sum.removed != 1 || sum.devices != 1 {
		t.Errorf("summary = %+v", sum)
	}
	if _, err := os.Stat(p.store.DeviceDir("b")); err != nil {
		t.Error("data of b removed during its poll")
	}
	p.done(b)
	if _, err := os.Stat(p.store.DeviceDir("b")); !os.IsNotExist(err) {
		t.Error("data of removed device b kept")
	}
}
