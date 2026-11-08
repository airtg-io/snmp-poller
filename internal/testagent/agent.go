// Package testagent runs an in-process SNMP agent (v1, v2c and v3 with
// every USM protocol, plus contexts) for integration tests.
package testagent

import (
	"net"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gosnmp/gosnmp"
	GoSNMPServer "github.com/slayercat/GoSNMPServer"
)

// Community is the v1/v2c community served by the default context.
const Community = "test-community"

// Passphrases used by every v3 user.
const (
	AuthPass = "auth-pass-123"
	PrivPass = "priv-pass-123"
)

// User is one SNMPv3 user known to the agent.
type User struct {
	Name string
	Auth gosnmp.SnmpV3AuthProtocol
	Priv gosnmp.SnmpV3PrivProtocol
}

// Value is a mutable OID value.
type Value struct {
	Type  gosnmp.Asn1BER
	Value any
}

// MIB is a set of OID values that tests can change between polls.
type MIB struct {
	mu   sync.Mutex
	vals map[string]Value
}

// NewMIB returns a MIB with the given initial values (OIDs without leading dot).
func NewMIB(vals map[string]Value) *MIB {
	m := &MIB{vals: map[string]Value{}}
	for k, v := range vals {
		m.vals[strings.TrimPrefix(k, ".")] = v
	}
	return m
}

// Set changes the value of an existing OID.
func (m *MIB) Set(oid string, v any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oid = strings.TrimPrefix(oid, ".")
	cur := m.vals[oid]
	cur.Value = v
	m.vals[oid] = cur
}

func (m *MIB) items() []*GoSNMPServer.PDUValueControlItem {
	oids := make([]string, 0, len(m.vals))
	for k := range m.vals {
		oids = append(oids, k)
	}
	sort.Strings(oids)
	items := make([]*GoSNMPServer.PDUValueControlItem, 0, len(oids))
	for _, oid := range oids {
		items = append(items, &GoSNMPServer.PDUValueControlItem{
			OID:  oid,
			Type: m.vals[oid].Type,
			OnGet: func() (any, error) {
				m.mu.Lock()
				defer m.mu.Unlock()
				return m.vals[oid].Value, nil
			},
		})
	}
	return items
}

// Agent is a running test agent.
type Agent struct {
	Port uint16
}

// Start serves def on the default context (community Community, empty v3
// context) and each entry of contexts under its v3 context name.
// The agent stops when the test ends.
func Start(t testing.TB, users []User, def *MIB, contexts map[string]*MIB) *Agent {
	t.Helper()
	usm := make([]gosnmp.UsmSecurityParameters, len(users))
	for i, u := range users {
		p := &usm[i]
		p.UserName = u.Name
		p.AuthenticationProtocol = u.Auth
		p.PrivacyProtocol = u.Priv
		if u.Auth != gosnmp.NoAuth {
			p.AuthenticationPassphrase = AuthPass
		}
		if u.Priv != gosnmp.NoPriv {
			p.PrivacyPassphrase = PrivPass
		}
	}
	subs := []*GoSNMPServer.SubAgent{{CommunityIDs: []string{Community, ""}, OIDs: def.items()}}
	for name, m := range contexts {
		subs = append(subs, &GoSNMPServer.SubAgent{CommunityIDs: []string{name}, OIDs: m.items()})
	}
	srv := GoSNMPServer.NewSNMPServer(GoSNMPServer.MasterAgent{
		Logger: GoSNMPServer.NewDiscardLogger(),
		SecurityConfig: GoSNMPServer.SecurityConfig{
			AuthoritativeEngineBoots: 1,
			Users:                    usm,
		},
		SubAgents: subs,
	})
	if err := srv.ListenUDP("udp", "127.0.0.1:0"); err != nil {
		t.Fatalf("test agent: %v", err)
	}
	go srv.ServeForever()
	t.Cleanup(srv.Shutdown)
	return &Agent{Port: uint16(srv.Address().(*net.UDPAddr).Port)}
}
