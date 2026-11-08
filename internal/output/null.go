package output

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/airtg-io/snmp-poller/internal/config"
)

func init() { Register("null", newNull) }

// Null discards every batch. It is the placeholder destination until real
// outputs exist, and is useful to benchmark polling alone.
type Null struct{}

func newNull(cfg config.Output, _ *slog.Logger) (Output, error) {
	if len(cfg.Options) > 0 {
		return nil, fmt.Errorf("null output takes no options")
	}
	return Null{}, nil
}

// Write discards b.
func (Null) Write(context.Context, *Batch) error { return nil }

// Close does nothing.
func (Null) Close() error { return nil }
