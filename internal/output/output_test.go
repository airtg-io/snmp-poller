package output

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/airtg-io/snmp-poller/internal/config"
)

func TestBuild(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	outs, err := Build([]config.Output{{Name: "a", Type: "null"}, {Name: "b", Type: "null"}}, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 2 {
		t.Fatalf("got %d outputs", len(outs))
	}
	if err := outs["a"].Write(context.Background(), &Batch{DeviceID: "d"}); err != nil {
		t.Error(err)
	}
	if err := CloseAll(outs); err != nil {
		t.Error(err)
	}

	if _, err := Build([]config.Output{{Name: "x", Type: "kafka"}}, log); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("err = %v", err)
	}
	if _, err := Build([]config.Output{{Name: "x", Type: "null", Options: map[string]any{"path": "/tmp"}}}, log); err == nil {
		t.Error("null output must reject options")
	}
}
