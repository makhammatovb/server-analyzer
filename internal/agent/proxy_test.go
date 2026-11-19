package agent_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

// PKI is a fleet CA plus a TLS server certificate it issued, standing in for
// the CA the real server holds and the certificate the real proxy serves.
type PKI struct {
	CA         *ca.CA
	CAPEM      []byte
	Pool       *x509.CertPool
	ServerCert tls.Certificate
}

// NewPKI builds a fresh CA and a server certificate for 127.0.0.1.
func NewPKI(t *testing.T) *PKI {
	t.Helper()
	certPEM, keyPEM, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	authority, err := ca.Load(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	caCert := mustParseCert(t, certPEM)
	caKey := mustParseKey(t, keyPEM)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fleetguard-test-proxy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &PKI{
		CA:         authority,
		CAPEM:      certPEM,
		Pool:       pool,
		ServerCert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: srvKey},
	}
}

func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func mustParseKey(t *testing.T, keyPEM []byte) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return k
}

// NewTestProxy starts a TLS server that stands in for the reverse proxy: it
// requests a client certificate in the handshake and, like the real proxy,
// overwrites X-Proxy-Auth with the shared secret and X-Agent-Cert with the
// base64 DER of the presented certificate (or removes it when none was
// presented) before calling backend. The agent knows neither header.
//
// It returns the server's base URL.
func NewTestProxy(t *testing.T, pki *PKI, proxySecret string, backend http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Proxy-Auth", proxySecret)
		r.Header.Del(api.AgentCertHeader)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			r.Header.Set(api.AgentCertHeader, base64.StdEncoding.EncodeToString(r.TLS.PeerCertificates[0].Raw))
		}
		backend.ServeHTTP(w, r)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.ServerCert},
		// Like Caddy's verify_if_given: no certificate is admitted, but one
		// that does not verify against the fleet CA (for instance an expired
		// one) fails the handshake.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pki.Pool,
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// HeartbeatBackend wraps the agent router with a stub POST /v1/heartbeat that
// answers 200 when X-Agent-Cert verifies against authority, 401 otherwise.
func HeartbeatBackend(authority *ca.CA, router http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		der, err := base64.StdEncoding.DecodeString(r.Header.Get(api.AgentCertHeader))
		if err != nil || len(der) == 0 {
			http.Error(w, "no certificate", http.StatusUnauthorized)
			return
		}
		if _, err := authority.Verify(der, time.Now()); err != nil {
			http.Error(w, "bad certificate", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.HeartbeatResponse{ConfigVersion: 1, PollIntervalSec: 30})
	})
	mux.Handle("/", router)
	return mux
}
