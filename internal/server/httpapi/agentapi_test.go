package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/internal/server/store"
	"github.com/makhammatovb/fleetguard/internal/server/store/storetest"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

const proxySecret = "test-proxy-secret" //nolint:gosec // test fixture, not a credential

func TestMain(m *testing.M) {
	code := m.Run()
	if err := storetest.TerminateTestDB(); err != nil {
		fmt.Fprintf(os.Stderr, "terminate test database: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

type env struct {
	st  *store.Store
	ca  *ca.CA
	srv *httptest.Server
}

func newEnv(t *testing.T) *env { return newEnvAt(t, time.Now) }

func newEnvAt(t *testing.T, now func() time.Time) *env {
	t.Helper()
	st := storetest.NewTestDB(t)
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(httpapi.NewAgentRouterAt(st, authority, proxySecret, lg, now))
	t.Cleanup(srv.Close)
	return &env{st: st, ca: authority, srv: srv}
}

func newCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored"},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// newServerWithToken registers a server and mints a token created at the
// given time, so tests can make tokens that are already expired.
func (e *env) newServerWithToken(t *testing.T, createdAt time.Time) (serverID, token string) {
	t.Helper()
	srv, err := e.st.CreateServer(context.Background(), "srv-"+uuid.NewString(), "")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	tok, err := e.st.CreateEnrolToken(context.Background(), srv.ID, time.Hour, createdAt)
	if err != nil {
		t.Fatalf("CreateEnrolToken: %v", err)
	}
	return srv.ID, tok
}

func (e *env) post(t *testing.T, path string, body any, withProxy bool) *http.Response {
	t.Helper()
	var raw []byte
	if b, ok := body.([]byte); ok {
		raw = b
	} else {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if withProxy {
		req.Header.Set("X-Proxy-Auth", proxySecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (e *env) enrol(t *testing.T, token string) (*http.Response, api.EnrolResponse) {
	t.Helper()
	resp := e.post(t, "/v1/enrol", api.EnrolRequest{
		Token: token, CSRPEM: newCSR(t), Hostname: "host-1", AgentVersion: "0.0.1",
	}, true)
	var out api.EnrolResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return resp, out
}

func certDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in certificate")
	}
	return block.Bytes
}

func countAudit(t *testing.T, e *env, action, target string) int {
	t.Helper()
	var n int
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = $1 AND target = $2`, action, target).Scan(&n)
	if err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func countAgents(t *testing.T, e *env, serverID string) int {
	t.Helper()
	var n int
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agents WHERE server_id = $1`, serverID).Scan(&n)
	if err != nil {
		t.Fatalf("count agents: %v", err)
	}
	return n
}

func TestEnrolIssuesCertificateForTokensServer(t *testing.T) {
	e := newEnv(t)
	serverID, token := e.newServerWithToken(t, time.Now())

	resp, out := e.enrol(t, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if out.ServerID != serverID {
		t.Fatalf("ServerID = %q, want %q", out.ServerID, serverID)
	}
	got, err := e.ca.Verify(certDER(t, out.CertPEM), time.Now())
	if err != nil || got != serverID {
		t.Fatalf("Verify = %q, %v; want %q", got, err, serverID)
	}
	if !bytes.Equal(out.CAPEM, e.ca.CertPEM()) {
		t.Fatal("CAPEM does not match the CA certificate")
	}
	if out.EnrolKey == "" {
		t.Fatal("EnrolKey empty")
	}
	if err := e.st.VerifyEnrolKey(context.Background(), serverID, out.EnrolKey); err != nil {
		t.Fatalf("returned EnrolKey does not verify against the store: %v", err)
	}
	if countAudit(t, e, "agent.enrolled", serverID) != 1 {
		t.Fatal("agent.enrolled not audited")
	}
}

func TestEnrolRejectsReplayedToken(t *testing.T) {
	e := newEnv(t)
	serverID, token := e.newServerWithToken(t, time.Now())

	if resp, _ := e.enrol(t, token); resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d", resp.StatusCode)
	}
	resp, _ := e.enrol(t, token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", resp.StatusCode)
	}
	if n := countAgents(t, e, serverID); n != 1 {
		t.Fatalf("agents rows = %d, want 1", n)
	}
}

func TestEnrolReplayIsAudited(t *testing.T) {
	e := newEnv(t)
	_, token := e.newServerWithToken(t, time.Now())
	e.enrol(t, token)

	var before int
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'agent.enrol_rejected'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	e.enrol(t, token)
	var after int
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'agent.enrol_rejected'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("enrol_rejected rows %d -> %d, want +1", before, after)
	}
}

func TestEnrolRejectsExpiredToken(t *testing.T) {
	e := newEnv(t)
	_, token := e.newServerWithToken(t, time.Now().Add(-2*time.Hour))
	resp, _ := e.enrol(t, token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestEnrolRejectsOversizedBody(t *testing.T) {
	e := newEnv(t)
	resp := e.post(t, "/v1/enrol", []byte(`{"token":"`+strings.Repeat("a", 1<<20)+`"}`), true)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestEnrolRejectsDecommissionedServer(t *testing.T) {
	e := newEnv(t)
	serverID, token := e.newServerWithToken(t, time.Now())
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE servers SET decommissioned_at = now() WHERE id = $1`, serverID); err != nil {
		t.Fatal(err)
	}
	resp, _ := e.enrol(t, token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (not 403)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(strings.ToLower(string(body)), "decommission") {
		t.Fatalf("response leaks the reason: %s", body)
	}
}

func TestEnrolRejectsMissingProxySecret(t *testing.T) {
	e := newEnv(t)
	serverID, token := e.newServerWithToken(t, time.Now())
	resp := e.post(t, "/v1/enrol", api.EnrolRequest{
		Token: token, CSRPEM: newCSR(t), Hostname: "h",
	}, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// The rejected request must not have burned the token.
	if resp, _ := e.enrol(t, token); resp.StatusCode != http.StatusOK {
		t.Fatalf("token was consumed by the unauthenticated request: %d", resp.StatusCode)
	}
	_ = serverID
}

func TestEnrolRejectsMalformedCSRWithoutBurningToken(t *testing.T) {
	e := newEnv(t)
	serverID, token := e.newServerWithToken(t, time.Now())
	resp := e.post(t, "/v1/enrol", api.EnrolRequest{
		Token: token, CSRPEM: []byte("not a csr"), Hostname: "h",
	}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	// A CSR with a corrupted signature is rejected the same way.
	good := newCSR(t)
	block, _ := pem.Decode(good)
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	resp = e.post(t, "/v1/enrol", api.EnrolRequest{
		Token: token, CSRPEM: pem.EncodeToMemory(block), Hostname: "h",
	}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("corrupt-signature status = %d, want 400", resp.StatusCode)
	}
	if r, out := e.enrol(t, token); r.StatusCode != http.StatusOK || out.ServerID != serverID {
		t.Fatalf("token was burned by the malformed CSR: status %d", r.StatusCode)
	}
}

func TestEnrolRejectsOversizedHostnameWithoutBurningToken(t *testing.T) {
	e := newEnv(t)
	_, token := e.newServerWithToken(t, time.Now())
	resp := e.post(t, "/v1/enrol", api.EnrolRequest{
		Token: token, CSRPEM: newCSR(t), Hostname: strings.Repeat("a", 254),
	}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if r, _ := e.enrol(t, token); r.StatusCode != http.StatusOK {
		t.Fatalf("token burned by the oversized hostname: %d", r.StatusCode)
	}
}

func TestRejectedEnrolAuditUsesConstantTarget(t *testing.T) {
	e := newEnv(t)
	hostname := "probe-" + uuid.NewString()
	resp := e.post(t, "/v1/enrol", api.EnrolRequest{
		Token: "no-such-token", CSRPEM: newCSR(t), Hostname: hostname,
	}, true)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var target, detail string
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT target, detail::text FROM audit_log
		  WHERE action = 'agent.enrol_rejected' AND detail->>'hostname' = $1`, hostname).Scan(&target, &detail)
	if err != nil {
		t.Fatalf("rejected-enrol audit row not found with hostname in detail: %v", err)
	}
	if target != "unknown" {
		t.Fatalf("target = %q, want the constant \"unknown\"", target)
	}
}

func enrolled(t *testing.T, e *env) (serverID string, out api.EnrolResponse) {
	t.Helper()
	id, token := e.newServerWithToken(t, time.Now())
	resp, out := e.enrol(t, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrol status = %d", resp.StatusCode)
	}
	return id, out
}

func TestReEnrolRejectsMissingProxySecret(t *testing.T) {
	e := newEnv(t)
	id, first := enrolled(t, e)
	resp := e.post(t, "/v1/re-enrol", api.ReEnrolRequest{
		ServerID: id, EnrolKey: first.EnrolKey, CSRPEM: newCSR(t),
	}, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestReEnrolWithValidSecretIssuesNewCert(t *testing.T) {
	e := newEnv(t)
	id, first := enrolled(t, e)
	resp := e.post(t, "/v1/re-enrol", api.ReEnrolRequest{
		ServerID: id, EnrolKey: first.EnrolKey, CSRPEM: newCSR(t),
	}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out api.EnrolResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if got, err := e.ca.Verify(certDER(t, out.CertPEM), time.Now()); err != nil || got != id {
		t.Fatalf("Verify = %q, %v; want %q", got, err, id)
	}
	oldFP := e.ca.Fingerprint(certDER(t, first.CertPEM))
	newFP := e.ca.Fingerprint(certDER(t, out.CertPEM))
	if oldFP == newFP {
		t.Fatal("re-enrolment returned the same certificate")
	}
	if countAudit(t, e, "agent.reenrolled", id) != 1 {
		t.Fatal("agent.reenrolled not audited")
	}
	var fp string
	var notAfter time.Time
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT cert_fingerprint, cert_not_after FROM agents WHERE server_id = $1`, id).Scan(&fp, &notAfter); err != nil {
		t.Fatal(err)
	}
	if fp != newFP {
		t.Fatalf("stored fingerprint = %q, want the re-issued %q", fp, newFP)
	}
	if want := time.Now().Add(89 * 24 * time.Hour); notAfter.Before(want) {
		t.Fatalf("stored cert_not_after = %v, want about 90 days out", notAfter)
	}
	// The secret keeps working: re-enrolment must not consume or change it.
	if err := e.st.VerifyEnrolKey(context.Background(), id, first.EnrolKey); err != nil {
		t.Fatalf("enrol key stopped verifying: %v", err)
	}
}

func TestReEnrolRejectsWrongSecret(t *testing.T) {
	e := newEnv(t)
	id, _ := enrolled(t, e)
	resp := e.post(t, "/v1/re-enrol", api.ReEnrolRequest{
		ServerID: id, EnrolKey: "not-the-secret", CSRPEM: newCSR(t),
	}, true)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if countAudit(t, e, "agent.reenrol_rejected", id) != 1 {
		t.Fatal("agent.reenrol_rejected not audited")
	}
}

func TestRequireProxySecretRejectsEmptySecret(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RequireProxySecret(\"\") did not panic")
		}
	}()
	httpapi.RequireProxySecret("")
}
