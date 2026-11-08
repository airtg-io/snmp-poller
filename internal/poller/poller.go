// Package poller schedules device polls on a bounded worker pool, runs
// discovery when due, and reports periodic statistics.
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
	"github.com/airtg-io/snmp-poller/internal/logging"
	"github.com/airtg-io/snmp-poller/internal/output"
	"github.com/airtg-io/snmp-poller/internal/state"
)

// Poller polls every configured device.
type Poller struct {
	cfg     config.Global
	log     *slog.Logger
	store   *state.Store
	devices []*device
	now     func() time.Time

	busy    []atomic.Bool
	stopped atomic.Bool
	stats   stats
}

// New prepares a poller. outputs must contain every output referenced by
// the configuration (see output.Build).
func New(cfg *config.Config, log *slog.Logger, outputs map[string]output.Output) (*Poller, error) {
	store, err := state.New(cfg.Global.DataDir)
	if err != nil {
		return nil, err
	}
	specs := cfg.DeviceSpecs()
	p := &Poller{
		cfg:   cfg.Global,
		log:   log,
		store: store,
		now:   time.Now,
		busy:  make([]atomic.Bool, len(specs)),
	}
	for _, spec := range specs {
		dl := log.With("device", spec.ID)
		if spec.Trace {
			dl = logging.WithMinLevel(dl, slog.LevelDebug)
		}
		d := &device{spec: spec, log: dl}
		for _, name := range spec.Outputs {
			o, ok := outputs[name]
			if !ok {
				return nil, fmt.Errorf("device %q: output %q not built", spec.ID, name)
			}
			d.outputs = append(d.outputs, o)
		}
		p.devices = append(p.devices, d)
	}
	return p, nil
}

// Run polls until ctx is cancelled, then waits up to shutdown_timeout for
// in-flight polls before aborting them.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.store.Clean(); err != nil {
		return fmt.Errorf("clean data dir: %w", err)
	}
	workers := min(p.cfg.Threads, max(len(p.devices), 1))
	p.log.Info("poller started", "devices", len(p.devices), "threads", p.cfg.Threads,
		"workers", workers, "data_dir", p.store.Dir())

	pollCtx, abort := context.WithCancel(context.WithoutCancel(ctx))
	defer abort()

	// Capacity = device count: a device is never queued twice, so the
	// scheduler never blocks on send.
	jobs := make(chan int, len(p.devices))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.work(pollCtx, jobs)
		}()
	}

	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		p.reportStats(ctx)
	}()

	p.schedule(ctx, jobs)

	p.stopped.Store(true)
	close(jobs)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	inflight := p.stats.inProgress.Load()
	p.log.Info("poller stopping", "in_progress", inflight, "queued", len(jobs))
	select {
	case <-done:
	case <-time.After(p.cfg.ShutdownTimeout):
		p.log.Warn("shutdown timeout reached, aborting in-flight polls",
			"in_progress", p.stats.inProgress.Load())
		abort()
		<-done
	}
	<-statsDone
	p.log.Info("poller stopped")
	return nil
}

// schedule dispatches each device every poll interval until ctx is done.
func (p *Poller) schedule(ctx context.Context, jobs chan<- int) {
	start := p.now()
	q := make(dueQueue, 0, len(p.devices))
	for i, d := range p.devices {
		// Spread first polls evenly over one interval to avoid bursts.
		offset := d.spec.PollInterval * time.Duration(i) / time.Duration(max(len(p.devices), 1))
		q = append(q, due{at: start.Add(offset), dev: i})
	}
	heap.Init(&q)
	if len(q) == 0 {
		// Nothing to poll: keep running (stats included) until asked to stop.
		<-ctx.Done()
		return
	}

	timer := time.NewTimer(0)
	defer timer.Stop()
	for len(q) > 0 {
		wait := q[0].at.Sub(p.now())
		timer.Reset(max(wait, 0))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := p.now()
		for len(q) > 0 && !q[0].at.After(now) {
			next := heap.Pop(&q).(due)
			d := p.devices[next.dev]
			if p.busy[next.dev].CompareAndSwap(false, true) {
				p.stats.queued.Add(1)
				jobs <- next.dev
			} else {
				p.stats.skipped.Add(1)
				d.log.Debug("poll skipped: previous poll still running")
			}
			// Keep the device's phase; skip slots already in the past.
			at := next.at.Add(d.spec.PollInterval)
			if behind := now.Sub(at); behind >= 0 {
				at = at.Add((behind/d.spec.PollInterval + 1) * d.spec.PollInterval)
			}
			heap.Push(&q, due{at: at, dev: next.dev})
		}
	}
}

func (p *Poller) work(ctx context.Context, jobs <-chan int) {
	for i := range jobs {
		p.stats.queued.Add(-1)
		if p.stopped.Load() {
			p.busy[i].Store(false)
			continue
		}
		p.stats.inProgress.Add(1)
		d := p.devices[i]
		start := p.now()
		res, err := d.poll(ctx, p.store, p.now)
		elapsed := p.now().Sub(start)
		p.stats.inProgress.Add(-1)
		p.stats.record(res, err, elapsed)
		p.track(d, res, err, elapsed)
		p.busy[i].Store(false)
	}
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

type due struct {
	at  time.Time
	dev int
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
