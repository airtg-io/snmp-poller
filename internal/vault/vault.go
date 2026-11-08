// Package vault reads device credentials from HashiCorp Vault's KV secrets
// engine (version 1 or 2) over its HTTP API. It logs in with the configured
// auth method (token, approle, userpass or kubernetes), shares one token
// between all devices, and logs in again before the token expires or when
// Vault rejects it.
//
// Error messages carry Vault's own error strings, never secret data.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
)

const maxBody = 1 << 20

// Client is a Vault client, safe for concurrent use.
type Client struct {
	cfg  config.Vault
	base string // address without trailing slash
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time // zero = never (static token, or no TTL)
}

// New returns a client for cfg. It does not contact Vault.
func New(cfg *config.Vault) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLSSkipVerify}
	if cfg.CACert != "" {
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("vault.ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("vault.ca_cert %s: no PEM certificate found", cfg.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &Client{
		cfg:  *cfg,
		base: strings.TrimSuffix(cfg.Address, "/"),
		http: &http.Client{Transport: tr, Timeout: cfg.Timeout},
		now:  time.Now,
	}, nil
}

// Read returns the key/value pairs of the KV secret at path (relative to the
// KV mount).
func (c *Client) Read(ctx context.Context, path string) (map[string]string, error) {
	tok, err := c.login(ctx, "")
	if err != nil {
		return nil, err
	}
	data, status, err := c.read(ctx, tok, path)
	if status == http.StatusForbidden && c.cfg.Auth.Method != config.VaultToken {
		// Token revoked or expired early: log in again, once.
		if tok, err = c.login(ctx, tok); err != nil {
			return nil, err
		}
		data, _, err = c.read(ctx, tok, path)
	}
	return data, err
}

func (c *Client) read(ctx context.Context, token, path string) (map[string]string, int, error) {
	api := escape(c.cfg.Mount) + "/" + escape(path)
	if c.cfg.KVVersion == 2 {
		api = escape(c.cfg.Mount) + "/data/" + escape(path)
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	status, err := c.do(ctx, http.MethodGet, api, token, nil, &resp)
	if status == http.StatusNotFound {
		return nil, status, fmt.Errorf("vault: no secret at %s/%s", c.cfg.Mount, path)
	}
	if err != nil {
		return nil, status, err
	}
	raw := resp.Data
	if c.cfg.KVVersion == 2 {
		var v2 struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &v2); err != nil {
			return nil, status, fmt.Errorf("vault: unexpected KV v2 response for %s (is kv_version right?)", path)
		}
		raw = v2.Data
	}
	var kv map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&kv); err != nil || kv == nil {
		return nil, status, fmt.Errorf("vault: secret %s has no data (is kv_version right?)", path)
	}
	out := make(map[string]string, len(kv))
	for k, v := range kv {
		switch v := v.(type) {
		case string:
			out[k] = v
		case json.Number:
			out[k] = v.String()
		default:
			return nil, status, fmt.Errorf("vault: secret %s: key %q must be a string", path, k)
		}
	}
	return out, status, nil
}

// login returns a valid token, logging in when there is none, when it is
// about to expire, or when it is stale (the token Vault just rejected).
func (c *Client) login(ctx context.Context, stale string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.cfg.Auth
	if a.Method == config.VaultToken {
		return a.Token.Reveal(), nil
	}
	if c.token != "" && c.token != stale && (c.expires.IsZero() || c.now().Before(c.expires)) {
		return c.token, nil
	}

	path := "auth/" + escape(a.Mount) + "/login"
	var body map[string]string
	switch a.Method {
	case config.VaultAppRole:
		body = map[string]string{"role_id": a.RoleID, "secret_id": a.SecretID.Reveal()}
	case config.VaultUserpass:
		path += "/" + url.PathEscape(a.Username)
		body = map[string]string{"password": a.Password.Reveal()}
	case config.VaultKubernetes:
		// Read on every login: the kubelet rotates the token.
		jwt, err := os.ReadFile(a.JWTFile)
		if err != nil {
			return "", fmt.Errorf("vault: kubernetes jwt: %w", err)
		}
		body = map[string]string{"role": a.Role, "jwt": strings.TrimSpace(string(jwt))}
	default:
		return "", fmt.Errorf("vault: unsupported auth method %q", a.Method)
	}
	var resp struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	start := c.now()
	if _, err := c.do(ctx, http.MethodPost, path, "", body, &resp); err != nil {
		return "", fmt.Errorf("vault login (%s): %w", a.Method, err)
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login (%s): no token in response", a.Method)
	}
	c.token = resp.Auth.ClientToken
	c.expires = time.Time{}
	if ttl := time.Duration(resp.Auth.LeaseDuration) * time.Second; ttl > 0 {
		// Log in again well before expiry: a read must never race it.
		c.expires = start.Add(ttl * 3 / 4)
	}
	return c.token, nil
}

// do sends a JSON request to /v1/<path> and decodes the JSON answer into
// out. Errors include Vault's error strings, never the body otherwise.
func (c *Client) do(ctx context.Context, method, path, token string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	// path is already escaped segment by segment.
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/v1/"+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Request", "true")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // the method and path are given below
		}
		return 0, fmt.Errorf("vault: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("vault: %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Errors []string `json:"errors"`
		}
		json.Unmarshal(data, &e)
		msg := strings.Join(e.Errors, "; ")
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("vault: %s %s: %d %s", method, path, resp.StatusCode, msg)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return resp.StatusCode, fmt.Errorf("vault: %s %s: invalid JSON response", method, path)
	}
	return resp.StatusCode, nil
}

// escape escapes each segment of a slash-separated path.
func escape(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
