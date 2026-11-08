package snmp

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// Kind classifies a converted value for delta computation.
type Kind string

// Value kinds.
const (
	KindCounter32 Kind = "counter32"
	KindCounter64 Kind = "counter64"
	KindUnsigned  Kind = "unsigned" // Gauge32, TimeTicks, Uinteger32
	KindInteger   Kind = "integer"
	KindFloat     Kind = "float"
	KindString    Kind = "string"
)

// Value is a decoded varbind.
type Value struct {
	Kind Kind
	// Type is the SNMP type name, e.g. "Counter64".
	Type  string
	Uint  uint64
	Int   int64
	Float float64
	Str   string
}

// Numeric reports whether the value can be used for rate/volume.
func (v Value) Numeric() bool { return v.Kind != KindString }

// Raw returns the natural Go value: uint64, int64, float64 or string.
func (v Value) Raw() any {
	switch v.Kind {
	case KindCounter32, KindCounter64, KindUnsigned:
		return v.Uint
	case KindInteger:
		return v.Int
	case KindFloat:
		return v.Float
	}
	return v.Str
}

// String formats the value as text (used for discovery labels).
func (v Value) String() string {
	if v.Kind == KindString {
		return v.Str
	}
	return fmt.Sprint(v.Raw())
}

// Convert decodes a PDU. ok is false for exception and null values.
func Convert(p gosnmp.SnmpPDU) (v Value, ok bool) {
	v.Type = p.Type.String()
	switch p.Type {
	case gosnmp.Counter32:
		v.Kind, v.Uint = KindCounter32, gosnmp.ToBigInt(p.Value).Uint64()
	case gosnmp.Counter64:
		v.Kind, v.Uint = KindCounter64, gosnmp.ToBigInt(p.Value).Uint64()
	case gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
		v.Kind, v.Uint = KindUnsigned, gosnmp.ToBigInt(p.Value).Uint64()
	case gosnmp.Integer:
		v.Kind, v.Int = KindInteger, gosnmp.ToBigInt(p.Value).Int64()
	case gosnmp.OpaqueFloat:
		f, _ := p.Value.(float32)
		v.Kind, v.Float = KindFloat, float64(f)
	case gosnmp.OpaqueDouble:
		f, _ := p.Value.(float64)
		v.Kind, v.Float = KindFloat, f
	case gosnmp.OctetString, gosnmp.BitString, gosnmp.Opaque:
		b, _ := p.Value.([]byte)
		v.Kind, v.Str = KindString, octets(b)
	case gosnmp.ObjectIdentifier, gosnmp.IPAddress:
		v.Kind, v.Str = KindString, fmt.Sprint(p.Value)
	default:
		return v, false
	}
	return v, true
}

// octets renders printable text as-is (trailing NULs trimmed) and binary
// data (MAC addresses, ...) as colon separated hex.
func octets(b []byte) string {
	t := strings.TrimRight(string(b), "\x00")
	if utf8.ValidString(t) && strings.IndexFunc(t, func(r rune) bool {
		return !unicode.IsPrint(r) && !unicode.IsSpace(r)
	}) < 0 {
		return t
	}
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}
