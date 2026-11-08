package snmp

import (
	"context"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/airtg-io/snmp-poller/internal/config"
)

func spec(t *testing.T, snmp string) *config.DeviceSpec {
	t.Helper()
	c, err := config.Parse(strings.NewReader(`devices: [{ id: d, address: 192.0.2.1, port: 1161, snmp: ` +
		snmp + `, scalars: [{ name: a, oid: 1.3 }] }]`))
	if err != nil {
		t.Fatal(err)
	}
	return &c.DeviceSpecs()[0]
}

func TestNewGoSNMPv3(t *testing.T) {
	g, err := NewGoSNMP(context.Background(), spec(t, `{ version: 3, transport: tcp, username: u,
		auth_protocol: SHA384, auth_passphrase: aaaaaaaa, priv_protocol: AES256C, priv_passphrase: bbbbbbbb,
		context_name: vrf-a, context_engine_id: "0x8000000001020304" }`))
	if err != nil {
		t.Fatal(err)
	}
	usm := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv || g.Transport != "tcp" || g.Port != 1161 ||
		usm.UserName != "u" || usm.AuthenticationProtocol != gosnmp.SHA384 || usm.PrivacyProtocol != gosnmp.AES256C ||
		usm.AuthenticationPassphrase != "aaaaaaaa" || usm.PrivacyPassphrase != "bbbbbbbb" ||
		g.ContextName != "vrf-a" || g.ContextEngineID != "\x80\x00\x00\x00\x01\x02\x03\x04" {
		t.Errorf("unexpected mapping: %+v usm=%+v", g, usm)
	}
}

func TestNewGoSNMPv3AuthNoPrivIgnoresPriv(t *testing.T) {
	g, err := NewGoSNMP(context.Background(), spec(t, `{ version: 3, username: u, security_level: authNoPriv,
		auth_protocol: MD5, auth_passphrase: aaaaaaaa, priv_protocol: DES, priv_passphrase: bbbbbbbb }`))
	if err != nil {
		t.Fatal(err)
	}
	usm := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.MsgFlags != gosnmp.AuthNoPriv || usm.PrivacyProtocol != gosnmp.NoPriv || usm.PrivacyPassphrase != "" {
		t.Errorf("priv must be ignored for authNoPriv: %+v", usm)
	}
}

func TestNewGoSNMPCommunity(t *testing.T) {
	for v, want := range map[string]gosnmp.SnmpVersion{"1": gosnmp.Version1, "2c": gosnmp.Version2c} {
		g, err := NewGoSNMP(context.Background(), spec(t, `{ version: "`+v+`", community: c0mm }`))
		if err != nil {
			t.Fatal(err)
		}
		if g.Version != want || g.Community != "c0mm" || g.Transport != "udp" {
			t.Errorf("v%s: %+v", v, g)
		}
	}
}

func TestConvert(t *testing.T) {
	for _, tc := range []struct {
		pdu  gosnmp.SnmpPDU
		kind Kind
		raw  any
	}{
		{gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(7)}, KindCounter32, uint64(7)},
		{gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(1 << 40)}, KindCounter64, uint64(1 << 40)},
		{gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint(3)}, KindUnsigned, uint64(3)},
		{gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint32(9)}, KindUnsigned, uint64(9)},
		{gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: -4}, KindInteger, int64(-4)},
		{gosnmp.SnmpPDU{Type: gosnmp.OpaqueDouble, Value: 1.5}, KindFloat, 1.5},
		{gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("eth0\x00")}, KindString, "eth0"},
		{gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte{0x00, 0x1a, 0x2b, 0xff}}, KindString, "00:1a:2b:ff"},
		{gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: "10.0.0.1"}, KindString, "10.0.0.1"},
		{gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6"}, KindString, ".1.3.6"},
	} {
		v, ok := Convert(tc.pdu)
		if !ok || v.Kind != tc.kind || v.Raw() != tc.raw {
			t.Errorf("%v: got %+v (%v), want %s %v", tc.pdu.Type, v, ok, tc.kind, tc.raw)
		}
	}
	for _, typ := range []gosnmp.Asn1BER{gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null} {
		if _, ok := Convert(gosnmp.SnmpPDU{Type: typ}); ok {
			t.Errorf("%v must not convert", typ)
		}
	}
}

func TestIndex(t *testing.T) {
	if idx, ok := Index(".1.3.6.1", ".1.3.6.1.5.2"); !ok || idx != "5.2" {
		t.Errorf("Index = %q %v", idx, ok)
	}
	if _, ok := Index(".1.3.6.1", ".1.3.6.10.1"); ok {
		t.Error("sibling column must not match")
	}
}
