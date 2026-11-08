// Package snmp wraps gosnmp with the poller's needs: mapping of the resolved
// configuration (v1, v2c, v3 with every auth/priv protocol and contexts),
// chunked GETs that tolerate missing OIDs, version-aware walks, and value
// conversion.
package snmp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/airtg-io/snmp-poller/internal/config"
)

var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	"":       gosnmp.NoAuth,
	"MD5":    gosnmp.MD5,
	"SHA":    gosnmp.SHA,
	"SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256,
	"SHA384": gosnmp.SHA384,
	"SHA512": gosnmp.SHA512,
}

var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	"":        gosnmp.NoPriv,
	"DES":     gosnmp.DES,
	"AES":     gosnmp.AES,
	"AES192":  gosnmp.AES192,
	"AES256":  gosnmp.AES256,
	"AES192C": gosnmp.AES192C,
	"AES256C": gosnmp.AES256C,
}

// Client is a connected SNMP session to one device. It is not safe for
// concurrent use; each poll opens its own.
type Client struct {
	g *gosnmp.GoSNMP
}

// NewGoSNMP maps a device spec onto a gosnmp session (not yet connected).
func NewGoSNMP(ctx context.Context, d *config.DeviceSpec) (*gosnmp.GoSNMP, error) {
	s := d.SNMP
	g := &gosnmp.GoSNMP{
		Context:        ctx,
		Target:         d.Address,
		Port:           d.Port,
		Transport:      s.Transport,
		Timeout:        d.Timeout,
		Retries:        d.Retries,
		MaxOids:        d.MaxOIDsPerRequest,
		MaxRepetitions: d.MaxRepetitions,
	}
	switch s.Version {
	case config.Version1:
		g.Version = gosnmp.Version1
		g.Community = s.Community.Reveal()
	case config.Version2c:
		g.Version = gosnmp.Version2c
		g.Community = s.Community.Reveal()
	case config.Version3:
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.ContextName = s.ContextName
		if s.ContextEngineID != "" {
			id, err := hex.DecodeString(s.ContextEngineID)
			if err != nil {
				return nil, errors.New("invalid context_engine_id")
			}
			g.ContextEngineID = string(id)
		}
		usm := &gosnmp.UsmSecurityParameters{
			UserName:               s.Username,
			AuthenticationProtocol: gosnmp.NoAuth,
			PrivacyProtocol:        gosnmp.NoPriv,
		}
		switch s.SecurityLevel {
		case config.NoAuthNoPriv:
			g.MsgFlags = gosnmp.NoAuthNoPriv
		case config.AuthNoPriv:
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationProtocol = authProtocols[s.AuthProtocol]
			usm.AuthenticationPassphrase = s.AuthPassphrase.Reveal()
		case config.AuthPriv:
			g.MsgFlags = gosnmp.AuthPriv
			usm.AuthenticationProtocol = authProtocols[s.AuthProtocol]
			usm.AuthenticationPassphrase = s.AuthPassphrase.Reveal()
			usm.PrivacyProtocol = privProtocols[s.PrivProtocol]
			usm.PrivacyPassphrase = s.PrivPassphrase.Reveal()
		}
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("unsupported version %q", s.Version)
	}
	return g, nil
}

// Dial opens a session to the device described by d.
func Dial(ctx context.Context, d *config.DeviceSpec) (*Client, error) {
	g, err := NewGoSNMP(ctx, d)
	if err != nil {
		return nil, err
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return &Client{g: g}, nil
}

// Close releases the session.
func (c *Client) Close() error {
	if c.g.Conn == nil {
		return nil
	}
	return c.g.Conn.Close()
}

// Get fetches oids, splitting them into requests of at most MaxOids
// varbinds. OIDs the agent does not have are silently omitted from the
// result (noSuchObject/noSuchInstance, or noSuchName on SNMPv1).
func (c *Client) Get(oids []string) ([]gosnmp.SnmpPDU, error) {
	var out []gosnmp.SnmpPDU
	max := c.g.MaxOids
	for start := 0; start < len(oids); start += max {
		end := min(start+max, len(oids))
		pdus, err := c.get(oids[start:end])
		if err != nil {
			return out, err
		}
		out = append(out, pdus...)
	}
	return out, nil
}

func (c *Client) get(oids []string) ([]gosnmp.SnmpPDU, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	pkt, err := c.g.Get(oids)
	if err != nil {
		return nil, err
	}
	switch pkt.Error {
	case gosnmp.NoError:
	case gosnmp.TooBig:
		if len(oids) == 1 {
			return nil, fmt.Errorf("get %s: response too big", oids[0])
		}
		return c.bisect(oids)
	case gosnmp.NoSuchName:
		// Non-compliant agents flag missing varbinds with exception values
		// and return the others: the response is usable as-is.
		if hasException(pkt.Variables) && len(pkt.Variables) == len(oids) {
			break
		}
		// SNMPv1 rejects the whole PDU: drop the offending OID and retry.
		if i := int(pkt.ErrorIndex) - 1; i >= 0 && i < len(oids) {
			rest := append(append([]string{}, oids[:i]...), oids[i+1:]...)
			return c.get(rest)
		}
		// Some agents do not say which OID is missing: bisect.
		if len(oids) == 1 {
			return nil, nil
		}
		return c.bisect(oids)
	default:
		return nil, fmt.Errorf("get: agent returned %s", pkt.Error)
	}
	out := pkt.Variables[:0]
	for _, v := range pkt.Variables {
		switch v.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func hasException(vars []gosnmp.SnmpPDU) bool {
	for _, v := range vars {
		switch v.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
			return true
		}
	}
	return false
}

func (c *Client) bisect(oids []string) ([]gosnmp.SnmpPDU, error) {
	half := len(oids) / 2
	a, err := c.get(oids[:half])
	if err != nil {
		return a, err
	}
	b, err := c.get(oids[half:])
	return append(a, b...), err
}

// Has reports whether the agent has at least one object below the subtree
// root, with a single GETNEXT. An agent answering an error status (SNMPv1
// noSuchName at the end of its MIB) does not have it.
func (c *Client) Has(root string) (bool, error) {
	pkt, err := c.g.GetNext([]string{root})
	if err != nil {
		return false, fmt.Errorf("getnext %s: %w", root, err)
	}
	switch pkt.Error {
	case gosnmp.NoError:
	case gosnmp.NoSuchName:
		return false, nil
	default:
		return false, fmt.Errorf("getnext %s: agent returned %s", root, pkt.Error)
	}
	if len(pkt.Variables) != 1 {
		return false, nil
	}
	v := pkt.Variables[0]
	switch v.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return false, nil
	}
	_, ok := Index(root, v.Name)
	return ok, nil
}

// Walk visits every OID below root: GETBULK on v2c/v3, GETNEXT on v1.
func (c *Client) Walk(root string, fn func(gosnmp.SnmpPDU) error) error {
	walk := c.g.BulkWalk
	if c.g.Version == gosnmp.Version1 {
		walk = c.g.Walk
	}
	err := walk(root, func(p gosnmp.SnmpPDU) error {
		switch p.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
			return nil
		}
		return fn(p)
	})
	if err != nil {
		return fmt.Errorf("walk %s: %w", root, err)
	}
	return nil
}

// Index returns the part of oid below column, without the leading dot, or
// false if oid is not inside column.
func Index(column, oid string) (string, bool) {
	if !strings.HasPrefix(oid, column+".") {
		return "", false
	}
	return oid[len(column)+1:], true
}
