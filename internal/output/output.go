// Package output defines where polled samples go. Outputs are pluggable:
// each type registers a factory, and the configuration instantiates any
// number of named outputs of any type.
package output

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// Sample is one emitted value.
type Sample struct {
	// Metric is the scalar name, or the table column name.
	Metric string
	// Table is the table name; empty for scalars.
	Table string
	// Index is the row index (OID suffix) for table samples; empty for scalars.
	Index string
	// Labels are discovery values attached to a table row (e.g. ifName).
	Labels map[string]string
	// Mode is raw, rate or volume.
	Mode config.Mode
	// Type is the SNMP type name of the polled value (e.g. Counter64).
	Type string
	// Value is the sample value: for raw mode an int64, uint64, float64 or
	// string depending on the SNMP type; for rate and volume a float64.
	Value any
	// Time is when the value was received.
	Time time.Time
}

// Batch is every sample produced by one poll of one device.
type Batch struct {
	DeviceID string
	Address  string
	// Discovery holds the device's discovery scalars (sysDescr, sysName, ...).
	Discovery map[string]string
	Samples   []Sample
}

// Output is a sample destination. Write is called concurrently by workers.
type Output interface {
	Write(ctx context.Context, b *Batch) error
	Close() error
}

// Factory builds an output from its configuration.
type Factory func(cfg config.Output, log *slog.Logger) (Output, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register makes an output type available to the configuration.
func Register(typ string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := factories[typ]; dup {
		panic("output: duplicate type " + typ)
	}
	factories[typ] = f
}

// Types lists registered output types.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for t := range factories {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Build instantiates every configured output, keyed by name.
func Build(cfgs []config.Output, log *slog.Logger) (map[string]Output, error) {
	mu.RLock()
	defer mu.RUnlock()
	outs := make(map[string]Output, len(cfgs))
	for _, c := range cfgs {
		f, ok := factories[c.Type]
		if !ok {
			CloseAll(outs)
			return nil, fmt.Errorf("output %q: unknown type %q (available: %v)", c.Name, c.Type, Types())
		}
		o, err := f(c, log.With("output", c.Name))
		if err != nil {
			CloseAll(outs)
			return nil, fmt.Errorf("output %q: %w", c.Name, err)
		}
		outs[c.Name] = o
	}
	return outs, nil
}

// CloseAll closes every output.
func CloseAll(outs map[string]Output) error {
	var errs []error
	for name, o := range outs {
		if err := o.Close(); err != nil {
			errs = append(errs, fmt.Errorf("output %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
