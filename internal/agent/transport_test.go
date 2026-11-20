package agent_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/makhammatovb/fleetguard/internal/agent"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

func TestClientSendsHeartbeatOverMutualTLS(t *testing.T) {
	e := newEnv(t)
	id := e.enrol(t)
	hb, err := agent.NewClient(id, e.cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: id.ServerID})
	if err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if hb.PollIntervalSec != 30 {
		t.Errorf("response = %+v", hb)
	}
}

func TestClientRejectsServerWithUntrustedCA(t *testing.T) {
	e := newEnv(t)
	id := e.enrol(t)

	foreign := NewPKI(t)
	url := NewTestProxy(t, foreign, proxySecret, http.NotFoundHandler())
	cfg := e.cfg
	cfg.ServerURL = url

	_, err := agent.NewClient(id, cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: id.ServerID})
	if err == nil {
		t.Fatal("client accepted a server certificate from a foreign CA")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error %q does not mention the certificate", err)
	}
}

func TestClientSendsClientCertificate(t *testing.T) {
	e := newEnv(t)
	id := e.enrol(t)

	chainLen := -1
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chainLen = len(r.TLS.PeerCertificates)
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{e.pki.ServerCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cfg := e.cfg
	cfg.ServerURL = srv.URL
	if _, err := agent.NewClient(id, cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: id.ServerID}); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if chainLen != 1 {
		t.Errorf("client certificate chain length = %d, want 1", chainLen)
	}
}

func TestClientDoesNotSendProxyOrCertHeaders(t *testing.T) {
	e := newEnv(t)
	id := e.enrol(t)

	var raw http.Header
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = r.Header.Clone()
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{e.pki.ServerCert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cfg := e.cfg
	cfg.ServerURL = srv.URL
	if _, err := agent.NewClient(id, cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: id.ServerID}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"X-Proxy-Auth", api.AgentCertHeader} {
		if v := raw.Get(h); v != "" {
			t.Errorf("agent sent %s", h)
		}
	}
}

func TestNewClientWithZeroIdentityRejectsServer(t *testing.T) {
	e := newEnv(t)
	_, err := agent.NewClient(agent.Identity{}, e.cfg).SendHeartbeat(context.Background(), api.Heartbeat{})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate error", err)
	}
}
