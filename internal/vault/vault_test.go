package vault

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/airtg-io/snmp-poller/internal/config"
	"github.com/airtg-io/snmp-poller/internal/testconf"
)

// fakeVault implements the login endpoints and a KV v1 or v2 engine.
type fakeVault struct {
	t       *testing.T
	kv      int
	secrets map[string]map[string]any // path under the mount -> data
	ttl     int

	mu       sync.Mutex
	logins   []string // login request paths
	bodies   []map[string]string
	valid    map[string]bool
	issued   int
	reads    int
	headers  http.Header
	failNext int // status for the next read
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = r.Header.Clone()
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
	}
	p := r.URL.Path
	if strings.HasPrefix(p, "/v1/auth/") {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		f.logins = append(f.logins, p)
		f.bodies = append(f.bodies, body)
		if body["secret_id"] == "bad" || body["password"] == "bad" {
			fail(400, "invalid credentials")
			return
		}
		f.issued++
		tok := fmt.Sprintf("tok-%d", f.issued)
		f.valid[tok] = true
		json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.ttl}})
		return
	}
	if !f.valid[r.Header.Get("X-Vault-Token")] {
		fail(403, "permission denied")
		return
	}
	f.reads++
	if f.failNext != 0 {
		fail(f.failNext, "injected")
		f.failNext = 0
		return
	}
	prefix := "/v1/secret/"
	if f.kv == 2 {
		prefix += "data/"
	}
	data, ok := f.secrets[strings.TrimPrefix(p, prefix)]
	if !strings.HasPrefix(p, prefix) || !ok {
		w.WriteHeader(404)
		w.Write([]byte(`{"errors":[]}`))
		return
	}
	var resp any = map[string]any{"data": data}
	if f.kv == 2 {
		resp = map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}}
	}
	json.NewEncoder(w).Encode(resp)
}

func start(t *testing.T, kv int, auth string) (*fakeVault, *Client) {
	t.Helper()
	f := &fakeVault{t: t, kv: kv, valid: map[string]bool{"static-token": true}, secrets: map[string]map[string]any{
		"snmp-poller/r1":      {"version": "3", "username": "poller", "auth_password": "s3cret-auth"},
		"odd/name with space": {"community": "c"},
		"numbers":             {"version": json.Number("2")},
		"nested":              {"x": map[string]any{"y": 1}},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg := testconf.Parse(t, fmt.Sprintf(`
vault:
  address: %s/
  namespace: team-a
  kv_version: %d
  auth: %s
devices: [{ address: x, snmp: { vault: true } }]
`, srv.URL, kv, auth), map[string]string{"uptime": testconf.Uptime})
	c, err := New(cfg.Vault)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestReadKV(t *testing.T) {
	for _, kv := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", kv), func(t *testing.T) {
			f, c := start(t, kv, `{ method: token, token: static-token }`)
			got, err := c.Read(context.Background(), "/snmp-poller/r1/")
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != "map[auth_password:s3cret-auth username:poller version:3]" {
				t.Errorf("secret = %v", got)
			}
			if f.headers.Get("X-Vault-Namespace") != "team-a" || f.headers.Get("X-Vault-Request") != "true" {
				t.Errorf("headers = %v", f.headers)
			}
			if got, err := c.Read(context.Background(), "odd/name with space"); err != nil || got["community"] != "c" {
				t.Errorf("escaped path: %v, %v", got, err)
			}
			if got, err := c.Read(context.Background(), "numbers"); err != nil || got["version"] != "2" {
				t.Errorf("number value: %v, %v", got, err)
			}
			if _, err := c.Read(context.Background(), "nested"); err == nil || !strings.Contains(err.Error(), `key "x" must be a string`) {
				t.Errorf("nested value: %v", err)
			}
			if _, err := c.Read(context.Background(), "missing/r9"); err == nil || err.Error() != "vault: no secret at secret/missing/r9" {
				t.Errorf("missing: %v", err)
			}
			if len(f.logins) != 0 {
				t.Errorf("token auth must not log in: %v", f.logins)
			}
		})
	}
}

func TestWrongKVVersion(t *testing.T) {
	_, c := start(t, 1, `{ method: token, token: static-token }`)
	c.cfg.KVVersion = 2 // the fake serves v1: /data/ paths do not exist
	if _, err := c.Read(context.Background(), "snmp-poller/r1"); err == nil {
		t.Error("expected an error")
	}
}

func TestLoginMethods(t *testing.T) {
	jwt := filepath.Join(t.TempDir(), "jwt")
	os.WriteFile(jwt, []byte("k8s-jwt\n"), 0o600)
	for _, tc := range []struct {
		auth, path, body string
	}{
		{`{ method: approle, role_id: r, secret_id: s3cret-id }`, "/v1/auth/approle/login", "map[role_id:r secret_id:s3cret-id]"},
		{`{ method: approle, mount: ci/approle, role_id: r, secret_id: x }`, "/v1/auth/ci/approle/login", "map[role_id:r secret_id:x]"},
		{`{ method: userpass, username: "u ser", password: p4ss }`, "/v1/auth/userpass/login/u ser", "map[password:p4ss]"},
		{`{ method: kubernetes, role: poller, jwt_file: ` + jwt + ` }`, "/v1/auth/kubernetes/login", "map[jwt:k8s-jwt role:poller]"},
	} {
		f, c := start(t, 2, tc.auth)
		if _, err := c.Read(context.Background(), "snmp-poller/r1"); err != nil {
			t.Errorf("%s: %v", tc.auth, err)
			continue
		}
		if fmt.Sprint(f.logins) != "["+tc.path+"]" || fmt.Sprint(f.bodies[0]) != tc.body {
			t.Errorf("%s: logins %v %v", tc.auth, f.logins, f.bodies)
		}
		if f.headers.Get("X-Vault-Token") != "tok-1" {
			t.Errorf("%s: token not used", tc.auth)
		}
	}
}

func TestTokenLifecycle(t *testing.T) {
	f, c := start(t, 2, `{ method: approle, role_id: r, secret_id: s }`)
	f.ttl = 100
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	read := func() {
		t.Helper()
		if _, err := c.Read(ctx, "snmp-poller/r1"); err != nil {
			t.Fatal(err)
		}
	}

	read()
	read()
	if len(f.logins) != 1 {
		t.Errorf("token not reused: %d logins", len(f.logins))
	}
	now = now.Add(76 * time.Second) // past 3/4 of the TTL
	read()
	if len(f.logins) != 2 {
		t.Errorf("token not renewed before expiry: %d logins", len(f.logins))
	}
	// Revoked token: one new login, and the read is retried.
	f.mu.Lock()
	f.valid = map[string]bool{}
	f.mu.Unlock()
	read()
	if len(f.logins) != 3 {
		t.Errorf("revoked token: %d logins", len(f.logins))
	}
	// A single 403 is retried after a new login.
	f.failNext = 403
	read()
	if len(f.logins) != 4 {
		t.Errorf("403: %d logins", len(f.logins))
	}
	// Vault denying the new token too: the error is reported, no loop.
	f.ttl = 0
	f.mu.Lock()
	f.valid = map[string]bool{}
	f.mu.Unlock()
	f.failNext = 403
	_, err := c.Read(ctx, "snmp-poller/r1")
	if err == nil || !strings.Contains(err.Error(), "403") || len(f.logins) != 5 {
		t.Errorf("err = %v after %d logins", err, len(f.logins))
	}
}

func TestConcurrentLoginOnce(t *testing.T) {
	f, c := start(t, 2, `{ method: approle, role_id: r, secret_id: s }`)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Read(context.Background(), "snmp-poller/r1"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(f.logins) != 1 {
		t.Errorf("%d logins, want 1", len(f.logins))
	}
}

func TestErrorsNeverLeakSecrets(t *testing.T) {
	_, c := start(t, 2, `{ method: approle, role_id: r, secret_id: bad }`)
	_, err := c.Read(context.Background(), "snmp-poller/r1")
	if err == nil || err.Error() != "vault login (approle): vault: POST auth/approle/login: 400 invalid credentials" {
		t.Errorf("err = %v", err)
	}

	_, c = start(t, 2, `{ method: token, token: wrong-token }`)
	_, err = c.Read(context.Background(), "snmp-poller/r1")
	if err == nil || err.Error() != "vault: GET secret/data/snmp-poller/r1: 403 permission denied" {
		t.Errorf("err = %v", err)
	}

	// Unreachable server.
	cfg := c.cfg
	cfg.Address = "http://127.0.0.1:1"
	c2, _ := New(&cfg)
	_, err = c2.Read(context.Background(), "snmp-poller/r1")
	if err == nil || strings.Contains(err.Error(), "wrong-token") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("err = %v", err)
	}
}

func TestCACert(t *testing.T) {
	f := &fakeVault{kv: 2, valid: map[string]bool{"static-token": true},
		secrets: map[string]map[string]any{"a": {"community": "c"}}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	cfg := config.Vault{Address: srv.URL, Mount: "secret", KVVersion: 2, Timeout: time.Second,
		Auth: config.VaultAuth{Method: config.VaultToken, Token: config.NewSecret("static-token")}}

	c, _ := New(&cfg)
	if _, err := c.Read(context.Background(), "a"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unknown CA must fail: %v", err)
	}

	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pemCert(srv), 0o644)
	cfg.CACert = ca
	c, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(context.Background(), "a"); err != nil {
		t.Errorf("with ca_cert: %v", err)
	}

	os.WriteFile(ca, []byte("not a cert"), 0o644)
	if _, err := New(&cfg); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("bad ca_cert: %v", err)
	}
}

func pemCert(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}
