package sink

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/airtg-io/schema"
	airtgv1 "github.com/airtg-io/schema/airtg/v1"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// AnalyzerURL is where airtg sinks publish: the NATS server of the AIrtg
// analyzer on this host, at NATS's default address. It is fixed on purpose
// and not configurable; it is a variable only so that tests can use their
// own server.
var AnalyzerURL = "nats://127.0.0.1:4222"

// Version is the poller's version, sent as the producer version of every
// envelope. Set by main.
var Version = "dev"

// ProducerType is the producer type of every envelope.
const ProducerType = "snmp-poller"

// maxSamplesBytes bounds the encoded samples of one MetricBatch, so that a
// message stays well under NATS's default max_payload (1MB): the samples of
// a poll are split into several batches beyond it.
const maxSamplesBytes = 512 << 10

// airtgEncoder encodes AIrtg schema envelopes: for each batch, an
// Inventory when the device was discovered since the last one sent, then
// one or more MetricBatch. Each envelope is one unit, framed with its
// subject and message id (see appendFrame), so a request body is a list of
// messages to publish.
type airtgEncoder struct {
	hostname string

	mu          sync.Mutex
	inventories map[string]time.Time // device id -> discovery time of the last inventory sent
}

func newAirtgEncoder() *airtgEncoder {
	host, _ := os.Hostname()
	return &airtgEncoder{hostname: host, inventories: map[string]time.Time{}}
}

func (*airtgEncoder) kind() byte { return kindAirtg }

// finish returns the frames as they are: envelopes are not compressed.
func (*airtgEncoder) finish(body []byte) []byte { return bytes.Clone(body) }

func (e *airtgEncoder) encode(buf []byte, b *Batch, units []unit) ([]byte, []unit, int) {
	dev := &airtgv1.Device{Id: b.DeviceID, Address: b.Address}

	// An inventory after every discovery: the batch carries the discovery
	// it was polled with, sent once.
	e.mu.Lock()
	sendInventory := !b.DiscoveredAt.IsZero() && !e.inventories[b.DeviceID].Equal(b.DiscoveredAt)
	if sendInventory {
		e.inventories[b.DeviceID] = b.DiscoveredAt
	}
	e.mu.Unlock()
	if sendInventory {
		inv := &airtgv1.Inventory{
			Device:       dev,
			DiscoveredAt: timestamppb.New(b.DiscoveredAt),
			Capabilities: slices.Sorted(slices.Values(b.Capabilities)),
			Scalars:      validMap(b.Discovery),
			Columns:      make(map[string]*airtgv1.Column, len(b.Columns)),
		}
		for name, rows := range b.Columns {
			inv.Columns[validUTF8(name)] = &airtgv1.Column{Rows: validMap(rows)}
		}
		buf = e.appendEnvelope(buf, schema.InventorySubject(b.DeviceID),
			&airtgv1.Envelope_Inventory{Inventory: inv})
		units = append(units, unit{end: len(buf), samples: 0})
	}

	n := 0
	var samples []*airtgv1.Sample
	size := 0
	flush := func() {
		if len(samples) == 0 {
			return
		}
		mb := &airtgv1.MetricBatch{Device: dev, Interval: durationpb.New(b.Interval), Samples: samples}
		buf = e.appendEnvelope(buf, schema.MetricsSubject(b.DeviceID), &airtgv1.Envelope_Metrics{Metrics: mb})
		units = append(units, unit{end: len(buf), samples: len(samples)})
		n += len(samples)
		samples, size = nil, 0
	}
	for i := range b.Samples {
		s := schemaSample(&b.Samples[i])
		if s == nil {
			continue
		}
		sz := proto.Size(s) + 1 + binary.MaxVarintLen32 // field tag and length
		if size+sz > maxSamplesBytes {
			flush()
		}
		samples = append(samples, s)
		size += sz
	}
	flush()
	return buf, units, n
}

// appendEnvelope wraps payload in an envelope and appends its frame.
func (e *airtgEncoder) appendEnvelope(buf []byte, subject string, payload any) []byte {
	env := &airtgv1.Envelope{
		Id:            newID(),
		SchemaVersion: schema.Version,
		Producer:      &airtgv1.Producer{Type: ProducerType, Version: Version, Hostname: e.hostname},
		Time:          timestamppb.Now(),
	}
	switch p := payload.(type) {
	case *airtgv1.Envelope_Metrics:
		env.Payload = p
	case *airtgv1.Envelope_Inventory:
		env.Payload = p
	}
	data, err := proto.Marshal(env)
	if err != nil {
		panic(err) // only invalid UTF-8 fails, and strings are made valid
	}
	return appendFrame(buf, subject, env.GetId(), data)
}

// schemaSample converts a sample; nil for a value type the schema has no
// field for.
func schemaSample(smp *Sample) *airtgv1.Sample {
	s := &airtgv1.Sample{
		Capability: validUTF8(smp.Capability),
		Metric:     validUTF8(smp.Metric),
		Table:      validUTF8(smp.Table),
		Index:      validUTF8(smp.Index),
		SourceType: validUTF8(smp.Type),
		Unit:       validUTF8(smp.Unit),
		Time:       timestamppb.New(smp.Time),
	}
	switch smp.Mode {
	case config.ModeRate:
		s.Mode = airtgv1.Mode_MODE_RATE
	case config.ModeVolume:
		s.Mode = airtgv1.Mode_MODE_VOLUME
	default:
		s.Mode = airtgv1.Mode_MODE_RAW
	}
	switch v := smp.Value.(type) {
	case int64:
		s.Value = &airtgv1.Sample_IntValue{IntValue: v}
	case uint64:
		s.Value = &airtgv1.Sample_UintValue{UintValue: v}
	case float64:
		s.Value = &airtgv1.Sample_DoubleValue{DoubleValue: v}
	case string:
		s.Value = &airtgv1.Sample_StringValue{StringValue: validUTF8(v)}
	default:
		return nil
	}
	s.Labels = validMap(smp.Labels)
	return s
}

// validMap returns m with valid UTF-8 keys and values; nil when empty.
func validMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[validUTF8(k)] = validUTF8(v)
	}
	return out
}

// validUTF8 replaces invalid UTF-8 (octet strings of devices may hold
// anything) with U+FFFD: protobuf strings must be valid UTF-8.
func validUTF8(s string) string {
	return string(bytes.ToValidUTF8([]byte(s), []byte("�")))
}

// newID returns a random (version 4) UUID.
func newID() string {
	var u [16]byte
	rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}

// A frame is one message to publish: subject, message id and data, each
// preceded by its length (uvarint).
func appendFrame(buf []byte, subject, id string, data []byte) []byte {
	for _, f := range [][]byte{[]byte(subject), []byte(id), data} {
		buf = binary.AppendUvarint(buf, uint64(len(f)))
		buf = append(buf, f...)
	}
	return buf
}

// frame is a decoded frame.
type frame struct {
	subject, id string
	data        []byte
}

// readFrames decodes a request body.
func readFrames(body []byte) ([]frame, error) {
	var frames []frame
	for len(body) > 0 {
		var f [3][]byte
		for i := range f {
			l, n := binary.Uvarint(body)
			if n <= 0 || uint64(len(body)-n) < l {
				return nil, errors.New("corrupt airtg record")
			}
			f[i], body = body[n:n+int(l)], body[n+int(l):]
		}
		frames = append(frames, frame{subject: string(f[0]), id: string(f[1]), data: f[2]})
	}
	return frames, nil
}

// natsClient publishes frames to the analyzer with JetStream, connecting on
// first use (New and -check never touch the network) and reconnecting
// forever. A publish succeeds once JetStream acknowledges it: the analyzer
// has stored it.
type natsClient struct {
	url     string
	timeout time.Duration

	mu sync.Mutex
	nc *nats.Conn
	js jetstream.JetStream
}

func (c *natsClient) connect() (jetstream.JetStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.js != nil {
		return c.js, nil
	}
	nc, err := nats.Connect(c.url,
		nats.Name(UserAgent),
		nats.RetryOnFailedConnect(true), // the analyzer may start later
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
		nats.ReconnectBufSize(-1), // fail while disconnected: the FIFO keeps the data
		nats.Timeout(c.timeout),
	)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	c.nc, c.js = nc, js
	return js, nil
}

// post publishes every message of payload, in order. An error makes the
// sender retry the whole payload: messages already stored are then dropped
// by JetStream as duplicates (same message id) within its duplicate window.
func (c *natsClient) post(ctx context.Context, payload []byte) error {
	frames, err := readFrames(payload)
	if err != nil {
		return &permanentError{body: err.Error()}
	}
	js, err := c.connect()
	if err != nil {
		return err
	}
	if !c.nc.IsConnected() {
		return c.notConnected()
	}
	for _, f := range frames {
		pctx, cancel := context.WithTimeout(ctx, c.timeout)
		_, err := js.PublishMsg(pctx, &nats.Msg{Subject: f.subject, Data: f.data}, jetstream.WithMsgID(f.id))
		cancel()
		switch {
		case err == nil:
		case !c.nc.IsConnected(), errors.Is(err, nats.ErrHeadersNotSupported), errors.Is(err, nats.ErrReconnectBufExceeded):
			// Lost meanwhile: what nats reports then (no server info, no
			// reconnect buffer) would only confuse.
			return c.notConnected()
		default:
			return natsError(f.subject, err)
		}
	}
	return nil
}

// notConnected describes why the client has no connection to the analyzer.
func (c *natsClient) notConnected() error {
	if err := c.nc.LastError(); err != nil {
		return fmt.Errorf("not connected to the analyzer: %w", err)
	}
	return fmt.Errorf("not connected to the analyzer (%s)", strings.ToLower(c.nc.Status().String()))
}

// natsError tells messages refused for good (too large, rejected by the
// stream) from failures worth retrying (no connection, no analyzer, no
// stream yet, timeout).
func natsError(subject string, err error) error {
	var api *jetstream.APIError
	switch {
	case errors.Is(err, nats.ErrMaxPayload):
		return &permanentError{body: fmt.Sprintf("%s: %v", subject, err)}
	case errors.As(err, &api) && api.Code == 400:
		return &permanentError{status: api.Code, body: fmt.Sprintf("%s: %v", subject, err)}
	}
	return fmt.Errorf("%s: %w", subject, err)
}

func (c *natsClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nc != nil {
		c.nc.Close()
		c.nc, c.js = nil, nil
	}
}
