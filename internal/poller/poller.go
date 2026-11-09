// Package poller schedules device polls on a bounded worker pool, runs
// discovery when due, reloads the configuration while running, and reports
// periodic statistics.
package poller

import (
	"container/heap"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/state"
)

// Poller polls every configured device.
type Poller struct {
	log   *slog.Logger
	store *state.Store
	now   func() time.Time
	stats stats

	// Configuration reload, see EnableReload and reload.go.
	load        func(path string) (*config.Config, error)
	logConfig   func(config.Logging) error
	reloadReq   chan struct{}
	watchEvery  time.Duration
	applies     chan *generation
	initial     []*device // devices to schedule when Run starts
	firstConfig *config.Config

	// mu protects the fields below, and the busy, removed, pending and
	// waiters fields of every device.
	mu       sync.Mutex
	cfg      config.Global
	conf     *config.Config
	devices  map[string]*device // by id
	count    atomic.Int64       // len(devices), for stats
	outputs  map[string]*outputEntry
	vault    *vaultEntry
	inflight map[string]*device // id -> device being polled (queued or running)
	queue    *jobQueue
	workers  int
	wg       sync.WaitGroup
	stopped  atomic.Bool
}

// New prepares a poller. outputs must contain every output of the
// configuration, built by output.Build; the poller owns them from then on
// (Run closes them, a reload closes those it replaces).
func New(cfg *config.Config, log *slog.Logger, outputs map[string]output.Output) (*Poller, error) {
	store, err := state.New(cfg.Global.DataDir)
	if err != nil {
		return nil, err
	}
	p := &Poller{
		log:         log,
		store:       store,
		now:         time.Now,
		reloadReq:   make(chan struct{}, 1),
		watchEvery:  2 * time.Second,
		applies:     make(chan *generation),
		firstConfig: cfg,
		devices:     map[string]*device{},
		outputs:     map[string]*outputEntry{},
		inflight:    map[string]*device{},
		queue:       newJobQueue(),
	}
	for _, o := range cfg.Outputs {
		out, ok := outputs[o.Name]
		if !ok {
			return nil, fmt.Errorf("output %q not built", o.Name)
		}
		p.outputs[o.Name] = &outputEntry{cfg: o, out: out}
	}
	gen, err := p.prepare(cfg)
	if err != nil {
		return nil, err
	}
	p.initial, _ = p.apply(gen)
	return p, nil
}

// Run polls until ctx is cancelled, then waits up to shutdown_timeout for
// in-flight polls before aborting them. Outputs are closed on return.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.store.Clean(); err != nil {
		return fmt.Errorf("clean data dir: %w", err)
	}
	p.mu.Lock()
	p.log.Info("poller started", "devices", len(p.devices), "threads", p.cfg.Threads,
		"workers", p.targetWorkers(), "data_dir", p.store.Dir())
	pollCtx, abort := context.WithCancel(context.WithoutCancel(ctx))
	defer abort()
	p.resize(pollCtx)
	p.mu.Unlock()

	var bg sync.WaitGroup
	bg.Add(1)
	go func() {
		defer bg.Done()
		p.reportStats(ctx)
	}()
	if p.load != nil {
		bg.Add(1)
		go func() {
			defer bg.Done()
			p.reloadLoop(ctx)
		}()
	}

	p.schedule(ctx, pollCtx)

	p.stopped.Store(true)
	queued := p.queue.close()
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	p.mu.Lock()
	timeout := p.cfg.ShutdownTimeout
	p.mu.Unlock()
	p.log.Info("poller stopping", "in_progress", p.stats.inProgress.Load(), "queued", queued)
	select {
	case <-done:
	case <-time.After(timeout):
		p.log.Warn("shutdown timeout reached, aborting in-flight polls",
			"in_progress", p.stats.inProgress.Load())
		abort()
		<-done
	}
	bg.Wait()
	p.mu.Lock()
	for name, e := range p.outputs {
		if err := e.out.Close(); err != nil {
			p.log.Error("closing output", "output", name, "err", err)
		}
	}
	p.mu.Unlock()
	p.log.Info("poller stopped")
	return nil
}

// targetWorkers is the size of the worker pool: global.threads, but never
// more than the number of devices. Called with p.mu held.
func (p *Poller) targetWorkers() int {
	return min(p.cfg.Threads, max(len(p.devices), 1))
}

// resize starts or stops workers to reach targetWorkers. A stopped worker
// finishes its current poll first. Called with p.mu held.
func (p *Poller) resize(ctx context.Context) {
	want := p.targetWorkers()
	for ; p.workers < want; p.workers++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.work(ctx)
		}()
	}
	if p.workers > want {
		p.queue.shrink(p.workers - want)
		p.workers = want
	}
}

// schedule dispatches each device every poll interval until ctx is done,
// and applies reloaded configurations.
func (p *Poller) schedule(ctx, pollCtx context.Context) {
	var q dueQueue
	p.spread(p.initial, p.now())
	p.initial = nil
	rebuild := func() {
		p.mu.Lock()
		q = q[:0]
		for _, d := range p.devices {
			q = append(q, due{at: d.next, dev: d})
		}
		p.mu.Unlock()
		heap.Init(&q)
	}
	rebuild()

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		var wake <-chan time.Time
		if len(q) > 0 {
			timer.Reset(max(q[0].at.Sub(p.now()), 0))
			wake = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case gen := <-p.applies:
			p.applyRunning(gen, pollCtx)
			rebuild()
			continue
		case <-wake:
		}
		now := p.now()
		for len(q) > 0 && !q[0].at.After(now) {
			next := heap.Pop(&q).(due)
			d := next.dev
			p.dispatch(d)
			// Keep the device's phase; skip slots already in the past.
			at := next.at.Add(d.interval)
			if behind := now.Sub(at); behind >= 0 {
				at = at.Add((behind/d.interval + 1) * d.interval)
			}
			d.next = at
			heap.Push(&q, due{at: at, dev: d})
		}
	}
}

// spread schedules the first poll of new devices evenly over one poll
// interval from now, to avoid bursts.
func (p *Poller) spread(devs []*device, now time.Time) {
	for i, d := range devs {
		d.next = now.Add(d.interval * time.Duration(i) / time.Duration(len(devs)))
	}
}

// dispatch queues a poll of d, unless the device (or a removed device with
// the same id) is still being polled.
func (p *Poller) dispatch(d *device) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inflight[d.spec.ID] != nil {
		p.stats.skipped.Add(1)
		d.log.Debug("poll skipped: previous poll still running")
		return
	}
	p.inflight[d.spec.ID] = d
	d.busy = true
	p.stats.queued.Add(1)
	p.queue.push(d)
}

func (p *Poller) work(ctx context.Context) {
	for {
		d, ok := p.queue.pop()
		if !ok {
			return
		}
		p.stats.queued.Add(-1)
		if !p.stopped.Load() {
			p.stats.inProgress.Add(1)
			start := p.now()
			res, err := d.poll(ctx, p.store, p.now)
			elapsed := p.now().Sub(start)
			p.stats.inProgress.Add(-1)
			p.stats.record(res, err, elapsed)
			p.track(d, res, err, elapsed)
		}
		p.done(d)
	}
}

// done ends the poll of d: pending configuration is applied, outputs
// retired meanwhile are closed when no poll uses them any more, and the
// data of a removed device is deleted.
func (p *Poller) done(d *device) {
	p.mu.Lock()
	d.busy = false
	delete(p.inflight, d.spec.ID)
	if d.pending != nil {
		d.applyConf(d.pending)
		d.pending = nil
	}
	var closing []*outputEntry
	for _, r := range d.waiters {
		if r.waiting--; r.waiting == 0 {
			closing = append(closing, r.outputs...)
		}
	}
	d.waiters = nil
	removeData := d.removed && p.devices[d.spec.ID] == nil
	if d.removed {
		p.forget(d)
	}
	p.mu.Unlock()
	if removeData {
		if err := p.store.ResetDevice(d.spec.ID); err != nil {
			p.log.Warn("removing the data of a removed device", "device", d.spec.ID, "err", err)
		}
	}
	p.closeOutputs(closing)
}

// track logs transitions only: the first failure of a device at warn level
// and its recovery at info level. Repeated failures are only counted in the
// periodic stats, so a dead device does not flood the logs.
func (p *Poller) track(d *device, res pollResult, err error, elapsed time.Duration) {
	if err != nil {
		if !d.failing {
			d.failing = true
			p.stats.failing.Add(1)
			d.log.Warn("poll failed", "address", d.spec.Address, "err", err)
		} else {
			d.log.Debug("poll failed", "err", err)
		}
		return
	}
	if d.failing {
		d.failing = false
		p.stats.failing.Add(-1)
		d.log.Info("poll recovered")
	}
	d.log.Debug("poll done", "duration", roundDur(elapsed),
		"samples", res.samples, "missing_oids", res.missing, "discovery", res.discovered)
}

// jobQueue is the queue of devices waiting for a worker. It is unbounded
// (a device is queued at most once, see dispatch) and can ask workers to
// exit, to shrink the pool.
type jobQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []*device
	quit   int // workers asked to exit
	closed bool
}

func newJobQueue() *jobQueue {
	q := &jobQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *jobQueue) push(d *device) {
	q.mu.Lock()
	q.items = append(q.items, d)
	q.mu.Unlock()
	q.cond.Signal()
}

// pop returns the next device to poll, or false when the worker must exit.
func (q *jobQueue) pop() (*device, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && q.quit == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.quit > 0 {
		q.quit--
		return nil, false
	}
	if len(q.items) == 0 {
		return nil, false // closed
	}
	d := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	return d, true
}

// shrink asks n workers to exit once their current poll is done.
func (q *jobQueue) shrink(n int) {
	q.mu.Lock()
	q.quit += n
	q.mu.Unlock()
	q.cond.Broadcast()
}

// close stops accepting work: queued devices are still handed to workers,
// which skip them (see work), and workers exit once the queue is empty.
// It returns the number of devices still queued.
func (q *jobQueue) close() int {
	q.mu.Lock()
	q.closed = true
	n := len(q.items)
	q.mu.Unlock()
	q.cond.Broadcast()
	return n
}

type due struct {
	at  time.Time
	dev *device
}

type dueQueue []due

func (q dueQueue) Len() int           { return len(q) }
func (q dueQueue) Less(i, j int) bool { return q[i].at.Before(q[j].at) }
func (q dueQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *dueQueue) Push(x any)        { *q = append(*q, x.(due)) }
func (q *dueQueue) Pop() any {
	old := *q
	x := old[len(old)-1]
	*q = old[:len(old)-1]
	return x
}

// roundDur keeps durations readable while preserving sub-millisecond values.
func roundDur(d time.Duration) time.Duration {
	if d < time.Millisecond {
		return d.Round(time.Microsecond)
	}
	return d.Round(time.Millisecond)
}
