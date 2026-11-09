package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/airtg-io/snmp-poller/internal/config"
)

// UserAgent is sent with every request.
var UserAgent = "airtg-snmp-poller"

// client posts payloads to one destination.
type client struct {
	http    *http.Client
	url     string
	headers http.Header
}

// permanentError is a request the destination refused for good (bad data):
// sending it again would fail again, so it is dropped.
type permanentError struct {
	status int
	body   string
}

func (e *permanentError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("HTTP %d", e.status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

func newClient(cfg *config.Sink) (*client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}
	if cfg.CACert != "" {
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert %s: no PEM certificate", cfg.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("client_cert/client_key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.MaxIdleConnsPerHost = 2

	c := &client{http: &http.Client{Transport: tr, Timeout: cfg.Timeout}, headers: http.Header{}}
	for k, v := range cfg.Headers {
		c.headers.Set(k, v)
	}
	c.headers.Set("User-Agent", UserAgent)
	switch cfg.Type {
	case config.SinkPrometheus:
		c.url = cfg.URL
		c.headers.Set("Content-Type", "application/x-protobuf")
		c.headers.Set("Content-Encoding", "snappy")
		c.headers.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
		if cfg.Token.IsSet() {
			c.headers.Set("Authorization", "Bearer "+cfg.Token.Reveal())
		}
	case config.SinkInfluxDB:
		u, err := url.Parse(cfg.URL)
		if err != nil {
			return nil, err
		}
		u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v2/write"
		u.RawQuery = url.Values{"bucket": {cfg.Database}, "precision": {"ms"}}.Encode()
		c.url = u.String()
		c.headers.Set("Content-Type", "text/plain; charset=utf-8")
		c.headers.Set("Content-Encoding", "gzip")
		if cfg.Token.IsSet() {
			c.headers.Set("Authorization", "Token "+cfg.Token.Reveal())
		}
	}
	if cfg.Username != "" {
		r := &http.Request{Header: http.Header{}}
		r.SetBasicAuth(cfg.Username, cfg.Password.Reveal())
		c.headers.Set("Authorization", r.Header.Get("Authorization"))
	}
	return c, nil
}

// post sends one payload. Errors are retryable (network, 5xx, 429, and
// 401/403/404 which a configuration fix solves), except *permanentError.
func (c *client) post(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header = c.headers.Clone()
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is logged with the sink, without its query
		}
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // reuse the connection
	if resp.StatusCode/100 == 2 {
		return nil
	}
	body := strings.Join(strings.Fields(string(msg)), " ")
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	if resp.StatusCode/100 == 4 {
		return &permanentError{status: resp.StatusCode, body: body}
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
}

func (c *client) close() { c.http.CloseIdleConnections() }
