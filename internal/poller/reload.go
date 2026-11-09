package poller

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/logging"
	"github.com/airtg-io/snmp-poller/internal/sink"
	"github.com/airtg-io/snmp-poller/internal/vault"
)

// EnableReload makes Run reload the configuration: when one of its files
// changes (global.hot_reload, checked every few seconds) and on Reload
// (SIGHUP). load reads and validates the configuration (config.Load).
// logConfig applies the logging section to the process logger; nil
// ignores it. A configuration that fails anywhere (validation, outputs,
// Vault, sinks, logging) is not applied: the previous one stays in force.
func (p *Poller) EnableReload(load func(path string) (*config.Config, error), logConfig func(config.Logging) error) {
	p.load, p.logConfig = load, logConfig
}

// Reload asks Run to reload the configuration now, whether or not its
// files changed. It does not wait.
func (p *Poller) Reload() {
	select {
	case p.reloadReq <- struct{}{}:
	default: // one is already pending
	}
}

// Seal encrypts the clear-text credentials of cfg's files in place and
// logs what it did. Failing to write a file is not fatal: polling works,
// that file stays in clear text.
func Seal(cfg *config.Config, log *slog.Logger) {
	sealed, err := cfg.Seal()
	if sealed.KeyCreated {
		log.Info("credentials key generated: back it up, encrypted credentials cannot be read without it",
			"key", sealed.KeyPath)
	}
	if err != nil {
		log.Warn("credentials not encrypted in the configuration", "key", sealed.KeyPath, "err", err)
	}
	if sealed.Encrypted > 0 {
		log.Info("credentials encrypted in the configuration", "files", strings.Join(sealed.Files, ","),
			"count", sealed.Encrypted, "key", sealed.KeyPath)
	}
}

// Sink is a destination of the batches of devices: a *sink.Sink, or a
// fake in tests.
type Sink interface {
	Write(b *sink.Batch)
	Start()
	Stats() sink.Stats
	Close() error
}

// sinkEntry is a built sink and the configuration it was built from.
type sinkEntry struct {
	cfg  config.Sink
	sink Sink
}

// openSink builds a sink and opens its disk buffer.
func openSink(cfg config.Sink, dataDir string, log *slog.Logger) (Sink, error) {
	s, err := sink.New(cfg, dataDir, log)
	if err != nil {
		return nil, fmt.Errorf("sink %q: %w", cfg.ID, err)
	}
	if err := s.Open(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// vaultEntry is the Vault client and the configuration it was built from.
type vaultEntry struct {
	cfg    *config.Vault
	client secretReader
}

// generation is a configuration ready to be applied: its sinks and Vault
// client are built.
type generation struct {
	cfg   *config.Config
	sinks map[string]*sinkEntry
	built []*sinkEntry // built for this generation, not reused
	vault *vaultEntry
	done  chan reloadSummary
}

// retirement is a set of sinks replaced by a reload, closed once every
// poll running at the time of the reload is done.
type retirement struct {
	sinks   []*sinkEntry
	waiting int
}

// deviceConf is what the configuration says about one device.
type deviceConf struct {
	spec  config.DeviceSpec
	key   string // spec.DiscoveryKey()
	log   *slog.Logger
	sinks []Sink
	vault secretReader
	// rediscover forgets the last discovery: the next poll discovers.
	rediscover bool
	// resetVault forgets the credentials read from Vault.
	resetVault bool
}

type reloadSummary struct {
	devices, added, removed, changed, rediscover int
}

// prepare builds what cfg needs that the running configuration does not
// have: sinks whose configuration is new or changed, and the Vault client
// when the vault section changed.
func (p *Poller) prepare(cfg *config.Config) (*generation, error) {
	p.mu.Lock()
	current, curVault := p.sinks, p.vault
	p.mu.Unlock()
	gen := &generation{cfg: cfg, sinks: map[string]*sinkEntry{}, done: make(chan reloadSummary, 1)}
	for _, k := range cfg.Sinks {
		if e := current[k.ID]; e != nil && e.cfg.Equal(&k) {
			gen.sinks[k.ID] = e
			continue
		}
		s, err := p.newSink(k, cfg.Global.DataDir, p.log)
		if err != nil {
			p.closeSinks(gen.built)
			return nil, err
		}
		e := &sinkEntry{cfg: k, sink: s}
		gen.sinks[k.ID], gen.built = e, append(gen.built, e)
	}
	usesVault := false
	for _, s := range cfg.DeviceSpecs() {
		usesVault = usesVault || s.VaultPath != ""
	}
	switch {
	case !usesVault:
	case curVault != nil && curVault.cfg.Equal(cfg.Vault):
		gen.vault = curVault // keeps its token
	default:
		c, err := vault.New(cfg.Vault)
		if err != nil {
			p.closeSinks(gen.built)
			return nil, err
		}
		gen.vault = &vaultEntry{cfg: cfg.Vault, client: c}
	}
	return gen, nil
}

// apply makes gen the running configuration and returns the new devices,
// to schedule. A device being polled gets its new configuration when the
// poll ends. Called before Run, or by the scheduler.
func (p *Poller) apply(gen *generation) ([]*device, reloadSummary) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	var sum reloadSummary
	p.cfg, p.conf = gen.cfg.Global, gen.cfg

	var retired []*sinkEntry
	for id, e := range p.sinks {
		if gen.sinks[id] != e {
			retired = append(retired, e)
		}
	}
	p.sinks, p.vault = gen.sinks, gen.vault
	for _, e := range gen.built {
		e.sink.Start() // takes over the disk buffer of the sink it replaces
	}

	var added []*device
	seen := map[string]bool{}
	for _, spec := range gen.cfg.DeviceSpecs() {
		seen[spec.ID] = true
		dc := p.deviceConf(spec)
		d := p.devices[spec.ID]
		if d == nil {
			d = &device{interval: spec.PollInterval}
			d.applyConf(dc)
			d.latest = dc
			p.devices[spec.ID] = d
			added = append(added, d)
			continue
		}
		prev := d.latest
		dc.rediscover = dc.key != prev.key
		dc.resetVault = spec.VaultPath != prev.spec.VaultPath
		if dc.rediscover {
			sum.rediscover++
		}
		if dc.rediscover || settings(dc) != settings(prev) {
			sum.changed++
		}
		if d.busy {
			if old := d.pending; old != nil {
				dc.rediscover = dc.rediscover || old.rediscover
				dc.resetVault = dc.resetVault || old.resetVault
			}
			d.pending = dc
		} else {
			d.applyConf(dc)
		}
		d.latest = dc
		// A shorter interval applies now; a longer one after the next poll.
		if spec.PollInterval != d.interval {
			d.interval = spec.PollInterval
			if limit := now.Add(d.interval); d.next.After(limit) {
				d.next = limit
			}
		}
	}

	var gone []string
	for id, d := range p.devices {
		if seen[id] {
			continue
		}
		d.removed = true
		delete(p.devices, id)
		sum.removed++
		if !d.busy {
			gone = append(gone, id)
			p.forget(d)
		}
	}
	sum.added, sum.devices = len(added), len(p.devices)
	p.count.Store(int64(len(p.devices)))

	if len(retired) > 0 {
		r := &retirement{sinks: retired}
		for _, d := range p.inflight {
			r.waiting++
			d.waiters = append(d.waiters, r)
		}
		if r.waiting == 0 {
			p.retire(retired)
		}
	}
	for _, id := range gone {
		if p.store != nil {
			if err := p.store.ResetDevice(id); err != nil {
				p.log.Warn("removing the data of a removed device", "device", id, "err", err)
			}
		}
	}
	return added, sum
}

// forget removes a removed device from the failing gauge. Called with p.mu
// held, once the device is not being polled.
func (p *Poller) forget(d *device) {
	if d.failing {
		d.failing = false
		p.stats.failing.Add(-1)
	}
}

// applyRunning applies gen while running: new devices are spread over
// their first interval and the worker pool is resized.
func (p *Poller) applyRunning(gen *generation, pollCtx context.Context) {
	added, sum := p.apply(gen)
	p.spread(added, p.now())
	p.mu.Lock()
	p.resize(pollCtx)
	p.mu.Unlock()
	gen.done <- sum
}

// deviceConf builds the configuration of one device from spec, with the
// sinks and Vault client of the generation being applied. Called with
// p.mu held, after p.sinks and p.vault are set.
func (p *Poller) deviceConf(spec config.DeviceSpec) *deviceConf {
	log := p.log.With("device", spec.ID)
	if spec.Trace {
		log = logging.WithMinLevel(log, slog.LevelDebug)
	}
	dc := &deviceConf{spec: spec, key: spec.DiscoveryKey(), log: log}
	for _, id := range spec.Sinks {
		dc.sinks = append(dc.sinks, p.sinks[id].sink)
	}
	if spec.VaultPath != "" && p.vault != nil {
		dc.vault = p.vault.client
	}
	return dc
}

// settings summarizes what a device's configuration sets besides its
// discovery key, to report changed devices.
func settings(dc *deviceConf) string {
	s := dc.spec
	str := fmt.Sprint(s.Walk, s.PollInterval, s.DiscoveryInterval, s.Timeout, s.Retries,
		s.MaxOIDsPerRequest, s.MaxRepetitions, s.Sinks, s.Trace)
	// Instances, not contents: a rebuilt sink or Vault client is a change.
	for _, k := range dc.sinks {
		str += fmt.Sprintf(" %p", k)
	}
	return str + fmt.Sprintf(" %p", dc.vault)
}

// retire closes sinks no poll uses any more, in the background: Run waits
// for them before returning.
func (p *Poller) retire(sinks []*sinkEntry) {
	if len(sinks) == 0 {
		return
	}
	p.closing.Go(func() { p.closeSinks(sinks) })
}

// closeSinks closes sinks, in parallel: each may
// take up to its timeout to send what it holds.
func (p *Poller) closeSinks(sinks []*sinkEntry) {
	var wg sync.WaitGroup
	for _, e := range sinks {
		wg.Go(func() {
			if err := e.sink.Close(); err != nil {
				p.log.Error("closing sink", "sink", e.cfg.ID, "err", err)
			}
		})
	}
	wg.Wait()
}

// reloadLoop reloads the configuration on Reload, and when its files
// change if global.hot_reload is set. A change must be seen on two checks
// in a row, so a file being written is not read half way.
func (p *Poller) reloadLoop(ctx context.Context) {
	t := time.NewTicker(p.watchEvery)
	defer t.Stop()
	cur := p.firstConfig
	last := cur.Fingerprint() // of the files as last loaded
	var changed, lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.reloadReq:
			cur, last = p.reload(ctx, cur, last, "signal")
			changed = ""
		case <-t.C:
			if !*cur.Global.HotReload {
				continue
			}
			fp, err := cur.DiskFingerprint()
			if err != nil {
				if err.Error() != lastErr {
					p.log.Warn("configuration files unreadable, not reloaded", "err", err)
				}
				lastErr = err.Error()
				continue
			}
			lastErr = ""
			switch {
			case fp == last:
				changed = ""
			case fp != changed:
				changed = fp // wait for the next check
			default:
				changed = ""
				cur, last = p.reload(ctx, cur, last, "file change")
			}
		}
	}
}

// reload loads, validates and applies the configuration. It returns the
// configuration in force and the fingerprint of the files last loaded: a
// configuration that failed is not loaded again until its files change.
func (p *Poller) reload(ctx context.Context, cur *config.Config, last, reason string) (*config.Config, string) {
	before, _ := cur.DiskFingerprint()
	fail := func(fp string, err error) (*config.Config, string) {
		p.log.Error("configuration reload failed, the previous configuration stays in force",
			"reason", reason, "err", err)
		return cur, fp
	}
	// Checked first: credentials are decrypted with the key of data_dir.
	if dir, err := config.DataDir(cur.Path()); err == nil && filepath.Clean(dir) != filepath.Clean(cur.Global.DataDir) {
		return fail(before, fmt.Errorf("global.data_dir changed from %s to %s: restart to apply it",
			cur.Global.DataDir, dir))
	}
	cfg, err := p.load(cur.Path())
	if err != nil {
		return fail(before, err)
	}
	Seal(cfg, p.log)
	gen, err := p.prepare(cfg)
	if err != nil {
		return fail(cfg.Fingerprint(), err)
	}
	if p.logConfig != nil {
		if err := p.logConfig(cfg.Logging); err != nil {
			p.closeSinks(gen.built)
			return fail(cfg.Fingerprint(), fmt.Errorf("logging: %w", err))
		}
	}
	select {
	case p.applies <- gen:
	case <-ctx.Done():
		p.closeSinks(gen.built)
		return cur, last
	}
	sum := <-gen.done
	p.log.Info("configuration reloaded", "reason", reason, "files", len(cfg.Files()),
		"devices", sum.devices, "added", sum.added, "removed", sum.removed,
		"changed", sum.changed, "rediscovered", sum.rediscover)
	return cfg, cfg.Fingerprint()
}
