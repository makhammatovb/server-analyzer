package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

const requestTimeout = 30 * time.Second

// Client makes authenticated outbound requests to the server. It presents the
// agent certificate in the TLS handshake and nothing else: the proxy secret
// and X-Agent-Cert header belong to the reverse proxy, never to the agent.
type Client struct {
	http    *http.Client
	baseURL string
}

// NewClient builds a client that verifies the server against id.CAPool and
// presents id.Cert as its client certificate.
func NewClient(id Identity, cfg Config) *Client {
	return &Client{
		http: newHTTPClient(&tls.Config{
			Certificates: []tls.Certificate{id.Cert},
			RootCAs:      id.CAPool,
			MinVersion:   tls.VersionTLS12,
		}),
		baseURL: cfg.ServerURL,
	}
}

// SendHeartbeat posts one heartbeat and returns the server's response.
func (c *Client) SendHeartbeat(ctx context.Context, hb api.Heartbeat) (api.HeartbeatResponse, error) {
	var out api.HeartbeatResponse
	if err := postJSON(ctx, c.http, c.baseURL+"/v1/heartbeat", hb, &out); err != nil {
		return api.HeartbeatResponse{}, fmt.Errorf("agent: heartbeat: %w", err)
	}
	return out, nil
}

// bootstrapClient is used for enrol and re-enrol, which are authenticated by a
// secret rather than a certificate. It presents no client certificate: an
// expired one would fail the proxy's handshake and block recovery.
func bootstrapClient(roots *x509.CertPool) *http.Client {
	return newHTTPClient(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
}

func newHTTPClient(tc *tls.Config) *http.Client {
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConns: 1, IdleConnTimeout: time.Minute},
		// Never follow redirects: a secret must not be replayed elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func postJSON(ctx context.Context, hc *http.Client, url string, body, out any) error {
	if err := validateServerURL(url); err != nil {
		return err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, api.MaxBodyBytes)).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
