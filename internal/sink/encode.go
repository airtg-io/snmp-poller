package sink

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"math"
	"strconv"
	"strings"

	"github.com/golang/snappy"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// encoder turns batches into request bodies. Encoded batches are
// concatenated (both formats allow it), then finish makes the request
// payload.
type encoder interface {
	// encode appends the samples of b the sink sends to buf and returns
	// how many it encoded.
	encode(buf []byte, b *Batch) ([]byte, int)
	// finish compresses a body made of encoded batches.
	finish(body []byte) []byte
	// kind identifies the format in the disk buffer.
	kind() byte
}

// Record kinds of the disk buffer.
const (
	kindPrometheus byte = 1
	kindInfluxDB   byte = 2
)

// promEncoder encodes Prometheus remote write 1.0 requests: a
// prometheus.WriteRequest (protobuf), snappy compressed. Each sample is a
// TimeSeries: name (prefix + key), its tags as labels, one sample.
type promEncoder struct{ sink *config.Sink }

func (*promEncoder) kind() byte { return kindPrometheus }

func (*promEncoder) finish(body []byte) []byte { return snappy.Encode(nil, body) }

func (e *promEncoder) encode(buf []byte, b *Batch) ([]byte, int) {
	n := 0
	var tv []tagValue
	var ts []byte
	for i := range b.Samples {
		smp := &b.Samples[i]
		key := config.SampleKey(smp.Metric, smp.Mode)
		if !e.sink.Sends(key) {
			continue
		}
		v, ok := numeric(smp.Value)
		if !ok {
			continue // Prometheus has no strings
		}
		tv = tags(e.sink, b, smp, tv[:0])
		ts = ts[:0]
		ts = appendLabel(ts, "__name__", config.PromName(*e.sink.Prefix+key)) // sorts first
		for _, t := range tv {
			ts = appendLabel(ts, config.PromName(t.name), t.value)
		}
		// Sample: value (double, field 1), timestamp in ms (int64, field 2).
		var sample [1 + 8 + 1 + binary.MaxVarintLen64]byte
		sample[0] = 0x09
		binary.LittleEndian.PutUint64(sample[1:], math.Float64bits(v))
		sample[9] = 0x10
		sl := 10 + binary.PutUvarint(sample[10:], uint64(smp.Time.UnixMilli()))
		ts = append(ts, 0x12)
		ts = binary.AppendUvarint(ts, uint64(sl))
		ts = append(ts, sample[:sl]...)
		// WriteRequest.timeseries (field 1).
		buf = append(buf, 0x0a)
		buf = binary.AppendUvarint(buf, uint64(len(ts)))
		buf = append(buf, ts...)
		n++
	}
	return buf, n
}

// appendLabel appends a TimeSeries.labels entry (field 1): a Label with
// name (field 1) and value (field 2).
func appendLabel(buf []byte, name, value string) []byte {
	size := 1 + uvarintLen(len(name)) + len(name) + 1 + uvarintLen(len(value)) + len(value)
	buf = append(buf, 0x0a)
	buf = binary.AppendUvarint(buf, uint64(size))
	buf = append(buf, 0x0a)
	buf = binary.AppendUvarint(buf, uint64(len(name)))
	buf = append(buf, name...)
	buf = append(buf, 0x12)
	buf = binary.AppendUvarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func uvarintLen(n int) int {
	l := 1
	for n >= 0x80 {
		n >>= 7
		l++
	}
	return l
}

// influxEncoder encodes InfluxDB line protocol, gzip compressed. The
// measurement is the table name, or the capability name for scalars (after
// the prefix); fields are the keys. The samples of one row (same
// measurement and tags) in a batch make one line, timestamped (ms) with
// the first of them.
type influxEncoder struct{ sink *config.Sink }

func (*influxEncoder) kind() byte { return kindInfluxDB }

func (*influxEncoder) finish(body []byte) []byte {
	var out bytes.Buffer
	w, _ := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	w.Write(body)
	w.Close()
	return out.Bytes()
}

type influxLine struct {
	series string // measurement and tags, escaped
	fields []byte
	keys   []string
	time   int64
}

func (e *influxEncoder) encode(buf []byte, b *Batch) ([]byte, int) {
	var lines []*influxLine
	byKey := map[string]*influxLine{}
	var tv []tagValue
	var sb strings.Builder
	n := 0
	for i := range b.Samples {
		smp := &b.Samples[i]
		key := config.SampleKey(smp.Metric, smp.Mode)
		if !e.sink.Sends(key) {
			continue
		}
		field, ok := influxValue(smp.Value)
		if !ok {
			continue
		}
		measurement := smp.Table
		if measurement == "" {
			measurement = smp.Capability
		}
		tv = tags(e.sink, b, smp, tv[:0])
		sb.Reset()
		escape(&sb, *e.sink.Prefix+measurement, ", ")
		for _, t := range tv {
			sb.WriteByte(',')
			escape(&sb, t.name, ",= ")
			sb.WriteByte('=')
			escape(&sb, t.value, ",= ")
		}
		series := sb.String()
		l := byKey[series]
		if l == nil {
			l = &influxLine{series: series, time: smp.Time.UnixMilli()}
			byKey[series] = l
			lines = append(lines, l)
		}
		if contains(l.keys, key) {
			continue
		}
		if len(l.keys) > 0 {
			l.fields = append(l.fields, ',')
		}
		sb.Reset()
		escape(&sb, key, ",= ")
		l.fields = append(l.fields, sb.String()...)
		l.fields = append(l.fields, '=')
		l.fields = append(l.fields, field...)
		l.keys = append(l.keys, key)
		n++
	}
	for _, l := range lines {
		buf = append(buf, l.series...)
		buf = append(buf, ' ')
		buf = append(buf, l.fields...)
		buf = append(buf, ' ')
		buf = strconv.AppendInt(buf, l.time, 10)
		buf = append(buf, '\n')
	}
	return buf, n
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// influxValue formats a field value: integers with the i suffix (uint64
// too, so a field never changes type with the SNMP type of the agent),
// floats, strings quoted. NaN and infinities are left out.
func influxValue(v any) (string, bool) {
	switch x := v.(type) {
	case int64:
		return strconv.FormatInt(x, 10) + "i", true
	case uint64:
		if x > math.MaxInt64 {
			return "", false
		}
		return strconv.FormatUint(x, 10) + "i", true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return "", false
		}
		return strconv.FormatFloat(x, 'g', -1, 64), true
	case string:
		var sb strings.Builder
		sb.WriteByte('"')
		for _, r := range noNewlines(x) {
			if r == '"' || r == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteRune(r)
		}
		sb.WriteByte('"')
		return sb.String(), true
	}
	return "", false
}

// escape writes s with a backslash before each character of special, as
// InfluxDB's own encoder does: a backslash is not escaped (C:\ Label is
// written C:\\ Label). Line breaks become spaces and trailing backslashes
// are dropped: line protocol has no way to write them.
func escape(sb *strings.Builder, s, special string) {
	for _, r := range strings.TrimRight(noNewlines(s), "\\") {
		if strings.ContainsRune(special, r) {
			sb.WriteByte('\\')
		}
		sb.WriteRune(r)
	}
}

func noNewlines(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
	}
	return s
}
