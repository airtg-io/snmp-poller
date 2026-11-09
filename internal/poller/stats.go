package poller

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// stats holds live gauges and per-interval counters.
type stats struct {
	inProgress atomic.Int64
	queued     atomic.Int64
	skipped    atomic.Int64
	failing    atomic.Int64

	mu       sync.Mutex
	interval counters
	total    counters
}

type counters struct {
	ok, failed               int64
	discoveries, discoFailed int64
	samples, outputErrs      int64
	durSum, durMax           time.Duration
}

func (s *stats) record(res pollResult, err error, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range []*counters{&s.interval, &s.total} {
		if err != nil {
			c.failed++
		} else {
			c.ok++
		}
		if res.discovered {
			c.discoveries++
		}
		if res.discoveryErr {
			c.discoFailed++
		}
		c.samples += int64(res.samples)
		c.outputErrs += int64(res.outputErrs)
		c.durSum += d
		c.durMax = max(c.durMax, d)
	}
}

// snapshot returns and resets the interval counters.
func (s *stats) snapshot() (interval, total counters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	interval, total = s.interval, s.total
	s.interval = counters{}
	return interval, total
}

// reportStats logs one summary line per stats interval until ctx is done,
// and a final one on exit. The interval is read again after each line, so
// a reload changes it.
func (p *Poller) reportStats(ctx context.Context) {
	last := p.now()
	for {
		p.mu.Lock()
		every := p.cfg.StatsInterval
		p.mu.Unlock()
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			p.logStats(p.now().Sub(last))
			return
		case <-t.C:
			now := p.now()
			p.logStats(now.Sub(last))
			last = now
		}
	}
}

func (p *Poller) logStats(window time.Duration) {
	iv, tot := p.stats.snapshot()
	polls := iv.ok + iv.failed
	var avg time.Duration
	if polls > 0 {
		avg = iv.durSum / time.Duration(polls)
	}
	p.log.Info("poller stats",
		"window", window.Round(time.Second),
		"devices", p.count.Load(),
		"in_progress", p.stats.inProgress.Load(),
		"queued", p.stats.queued.Load(),
		"failing_devices", p.stats.failing.Load(),
		"polls_ok", iv.ok,
		"polls_failed", iv.failed,
		"skipped", p.stats.skipped.Swap(0),
		"discoveries", iv.discoveries,
		"discovery_failed", iv.discoFailed,
		"samples", iv.samples,
		"output_errors", iv.outputErrs,
		"avg_duration", roundDur(avg),
		"max_duration", roundDur(iv.durMax),
		"total_polls_ok", tot.ok,
		"total_polls_failed", tot.failed,
	)
}
