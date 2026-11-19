package agent_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/agent"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/internal/server/store"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

const proxySecret = "test-proxy-secret" //nolint:gosec // test fixture, not a credential

func TestMain(m *testing.M) {
	code := m.Run()
	if err := store.TerminateTestDB(); err != nil {
		fmt.Fprintf(os.Stderr, "terminate test database: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

type env struct {
	st  *store.Store
	pki *PKI
	cfg agent.Config
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := store.NewTestDB(t)
	pki := NewPKI(t)
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := httpapi.NewAgentRouter(st, pki.CA, proxySecret, lg)
	url := NewTestProxy(t, pki, proxySecret, HeartbeatBackend(pki.CA, router))
	cfg := agent.Config{
		ServerURL:    url,
		StateDir:     filepath.Join(t.TempDir(), "state"),
		PollInterval: 30 * time.Second,
	}
	// The installer places ca.crt before enrolling; it is the agent's pin.
	placeCA(t, cfg.StateDir, pki.CAPEM)
	return &env{st: st, pki: pki, cfg: cfg}
}

func placeCA(t *testing.T, stateDir string, caPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "ca.crt"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *env) token(t *testing.T) string {
	t.Helper()
	srv, err := e.st.CreateServer(context.Background(), "srv-"+strings.ReplaceAll(t.Name(), "/", "-"), "")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	tok, err := e.st.CreateEnrolToken(context.Background(), srv.ID, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("CreateEnrolToken: %v", err)
	}
	return tok
}

func (e *env) enrol(t *testing.T) agent.Identity {
	t.Helper()
	id, err := agent.Enrol(context.Background(), e.cfg, e.token(t), "host-1", "0.0.1")
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	return id
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test path under TempDir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestEnrolPersistsIdentityWith0600(t *testing.T) {
	e := newEnv(t)
	e.enrol(t)

	for _, name := range []string{"agent.crt", "agent.key", "ca.crt", "enrol.key", "server_id"} {
		fi, err := os.Stat(filepath.Join(e.cfg.StateDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, fi.Mode().Perm())
		}
	}
	fi, err := os.Stat(e.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %o, want 700", fi.Mode().Perm())
	}
	if len(bytes.TrimSpace(readFile(t, filepath.Join(e.cfg.StateDir, "enrol.key")))) == 0 {
		t.Error("enrol.key is empty")
	}
}

func TestLoadIdentityAfterEnrolReturnsSameServerID(t *testing.T) {
	e := newEnv(t)
	enrolled := e.enrol(t)

	loaded, err := agent.LoadIdentity(e.cfg)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.ServerID != enrolled.ServerID || loaded.ServerID == "" {
		t.Errorf("server id = %q, want %q", loaded.ServerID, enrolled.ServerID)
	}
	if !loaded.NotAfter.Equal(enrolled.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", loaded.NotAfter, enrolled.NotAfter)
	}
	// The recovered identity must actually work.
	hb, err := agent.NewClient(loaded, e.cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: loaded.ServerID})
	if err != nil || hb.ConfigVersion != 1 {
		t.Fatalf("heartbeat with loaded identity: %+v, %v", hb, err)
	}
}

func TestLoadIdentityWithoutStateReturnsErrNoIdentity(t *testing.T) {
	cfg := agent.Config{StateDir: filepath.Join(t.TempDir(), "absent")}
	if _, err := agent.LoadIdentity(cfg); !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
	empty := agent.Config{StateDir: t.TempDir()}
	if _, err := agent.LoadIdentity(empty); !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("empty dir: err = %v, want ErrNoIdentity", err)
	}
}

func TestNeedsRotationAtSixtyDays(t *testing.T) {
	e := newEnv(t)
	id := e.enrol(t)
	issued := id.NotAfter.Add(-90 * 24 * time.Hour)

	if id.NeedsRotation(issued.Add(59 * 24 * time.Hour)) {
		t.Error("NeedsRotation at day 59 = true, want false")
	}
	if !id.NeedsRotation(issued.Add(61 * 24 * time.Hour)) {
		t.Error("NeedsRotation at day 61 = false, want true")
	}
	if !id.NeedsRotation(id.NotAfter.Add(time.Hour)) {
		t.Error("NeedsRotation after expiry = false, want true")
	}
}

func TestReEnrolRecoversFromExpiredCertificate(t *testing.T) {
	e := newEnv(t)
	enrolled := e.enrol(t)

	// Replace agent.crt with an already expired certificate. The test CA is
	// minutes old, so a short TTL (not a backdated issue time) keeps the
	// certificate no older than its issuer.
	expiredPEM, err := e.pki.CA.Sign(csrFor(t, filepath.Join(e.cfg.StateDir, "agent.key")), enrolled.ServerID,
		30*time.Second, time.Now())
	if err != nil {
		t.Fatalf("sign expired: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e.cfg.StateDir, "agent.crt"), expiredPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	stale, err := agent.LoadIdentity(e.cfg)
	if err != nil {
		t.Fatalf("LoadIdentity with expired cert: %v", err)
	}
	if !stale.NeedsRotation(time.Now()) {
		t.Fatal("expired identity must need rotation")
	}
	_, err = agent.NewClient(stale, e.cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: stale.ServerID})
	if err == nil {
		t.Fatal("heartbeat with an expired certificate unexpectedly succeeded")
	}
	// The proxy rejects it in the handshake, as Caddy's verify_if_given does,
	// not with an HTTP status: this is why ReEnrol must present no certificate.
	if strings.Contains(err.Error(), "server returned") {
		t.Fatalf("expected a handshake failure, got an HTTP response: %v", err)
	}

	id, err := agent.ReEnrol(context.Background(), e.cfg)
	if err != nil {
		t.Fatalf("ReEnrol: %v", err)
	}
	if id.ServerID != enrolled.ServerID {
		t.Errorf("server id changed: %q -> %q", enrolled.ServerID, id.ServerID)
	}
	if id.NeedsRotation(time.Now()) {
		t.Error("fresh identity already needs rotation")
	}
	if _, err := agent.NewClient(id, e.cfg).SendHeartbeat(context.Background(), api.Heartbeat{ServerID: id.ServerID}); err != nil {
		t.Fatalf("heartbeat after ReEnrol: %v", err)
	}
	// The new identity was persisted.
	loaded, err := agent.LoadIdentity(e.cfg)
	if err != nil || !loaded.NotAfter.Equal(id.NotAfter) {
		t.Fatalf("persisted identity not updated: %v", err)
	}
}

func TestReEnrolKeepsEnrolKeyByteIdentical(t *testing.T) {
	e := newEnv(t)
	e.enrol(t)
	path := filepath.Join(e.cfg.StateDir, "enrol.key")
	before := readFile(t, path)
	if len(before) == 0 {
		t.Fatal("enrol.key empty after Enrol")
	}

	if _, err := agent.ReEnrol(context.Background(), e.cfg); err != nil {
		t.Fatalf("ReEnrol: %v", err)
	}
	if after := readFile(t, path); !bytes.Equal(before, after) {
		t.Fatal("enrol.key changed across ReEnrol")
	}
	// And it still works a second time, proving the secret was not clobbered.
	if _, err := agent.ReEnrol(context.Background(), e.cfg); err != nil {
		t.Fatalf("second ReEnrol: %v", err)
	}
}

func TestReEnrolWithoutIdentityFails(t *testing.T) {
	cfg := agent.Config{ServerURL: "https://127.0.0.1:1", StateDir: t.TempDir()}
	if _, err := agent.ReEnrol(context.Background(), cfg); !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
}

func TestEnrolRejectedTokenWritesNothing(t *testing.T) {
	e := newEnv(t)
	_, err := agent.Enrol(context.Background(), e.cfg, "not-a-real-token", "host-1", "0.0.1")
	if err == nil {
		t.Fatal("Enrol with bad token succeeded")
	}
	if _, err := agent.LoadIdentity(e.cfg); !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("identity after failed enrol: %v", err)
	}
}

func TestEnrolRefusesPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	cfg := agent.Config{ServerURL: srv.URL, StateDir: t.TempDir()}
	placeCA(t, cfg.StateDir, NewPKI(t).CAPEM)
	if _, err := agent.Enrol(context.Background(), cfg, "tok", "host-1", "0.0.1"); err == nil {
		t.Fatal("Enrol over http succeeded")
	}
}

// csrFor builds a CSR for the private key stored at keyPath.
func csrFor(t *testing.T, keyPath string) []byte {
	t.Helper()
	key := mustParseKey(t, readFile(t, keyPath))
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestEnrolWithoutCACrtIsHardError(t *testing.T) {
	e := newEnv(t)
	if err := os.Remove(filepath.Join(e.cfg.StateDir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	_, err := agent.Enrol(context.Background(), e.cfg, e.token(t), "host-1", "0.0.1")
	if !errors.Is(err, agent.ErrNoCA) {
		t.Fatalf("err = %v, want ErrNoCA", err)
	}
}

func TestEnrolWithUnparseableCACrtIsHardError(t *testing.T) {
	e := newEnv(t)
	placeCA(t, e.cfg.StateDir, []byte("not a certificate"))
	_, err := agent.Enrol(context.Background(), e.cfg, e.token(t), "host-1", "0.0.1")
	if !errors.Is(err, agent.ErrNoCA) {
		t.Fatalf("err = %v, want ErrNoCA", err)
	}
}

// The pin: ca.crt names a CA other than the one the server certificate chains
// to, so the agent must refuse to talk to it and spend no token.
func TestEnrolRejectsServerNotIssuedByPinnedCA(t *testing.T) {
	e := newEnv(t)
	placeCA(t, e.cfg.StateDir, NewPKI(t).CAPEM)
	tok := e.token(t)
	_, err := agent.Enrol(context.Background(), e.cfg, tok, "host-1", "0.0.1")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate verification error", err)
	}
	// Token unspent: enrolling with the right pin still works.
	placeCA(t, e.cfg.StateDir, e.pki.CAPEM)
	if _, err := agent.Enrol(context.Background(), e.cfg, tok, "host-1", "0.0.1"); err != nil {
		t.Fatalf("enrol with correct pin: %v", err)
	}
}

func TestLoadIdentityWithoutCACrtReturnsErrNoCA(t *testing.T) {
	e := newEnv(t)
	e.enrol(t)
	if err := os.Remove(filepath.Join(e.cfg.StateDir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LoadIdentity(e.cfg); !errors.Is(err, agent.ErrNoCA) {
		t.Fatalf("err = %v, want ErrNoCA", err)
	}
}

// fakeEnrolBackend answers /v1/enrol with a certificate issued by issuer and
// the given ca_pem, standing in for a server that is misconfigured or lying.
func fakeEnrolBackend(t *testing.T, issuer *PKI, caPEM []byte) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enrol", func(w http.ResponseWriter, r *http.Request) {
		var req api.EnrolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		certPEM, err := issuer.CA.Sign(req.CSRPEM, uuid.NewString(), 90*24*time.Hour, time.Now())
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(api.EnrolResponse{
			ServerID: uuid.NewString(), CertPEM: certPEM, CAPEM: caPEM, EnrolKey: "k",
		})
	})
	return mux
}

func TestEnrolRejectsCertificateNotChainingToPin(t *testing.T) {
	pinned := NewPKI(t)
	other := NewPKI(t)
	// ca_pem claims the pinned CA, but the certificate comes from another CA.
	url := NewTestProxy(t, pinned, proxySecret, fakeEnrolBackend(t, other, pinned.CAPEM))
	cfg := agent.Config{ServerURL: url, StateDir: filepath.Join(t.TempDir(), "state")}
	placeCA(t, cfg.StateDir, pinned.CAPEM)

	_, err := agent.Enrol(context.Background(), cfg, "tok", "host-1", "0.0.1")
	if !errors.Is(err, agent.ErrCertNotPinned) {
		t.Fatalf("err = %v, want ErrCertNotPinned", err)
	}
	if _, err := agent.LoadIdentity(cfg); !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("identity persisted after rejected enrolment: %v", err)
	}
}

func TestEnrolRejectsCAPEMThatDiffersFromPin(t *testing.T) {
	pinned := NewPKI(t)
	other := NewPKI(t)
	// Certificate and ca_pem agree with each other but not with the pin.
	url := NewTestProxy(t, pinned, proxySecret, fakeEnrolBackend(t, other, other.CAPEM))
	cfg := agent.Config{ServerURL: url, StateDir: filepath.Join(t.TempDir(), "state")}
	placeCA(t, cfg.StateDir, pinned.CAPEM)

	_, err := agent.Enrol(context.Background(), cfg, "tok", "host-1", "0.0.1")
	if !errors.Is(err, agent.ErrCAMismatch) {
		t.Fatalf("err = %v, want ErrCAMismatch", err)
	}
	if _, err := agent.LoadIdentity(cfg); !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("identity persisted after rejected enrolment: %v", err)
	}
}
