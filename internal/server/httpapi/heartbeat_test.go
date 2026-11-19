package httpapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

// heartbeat posts hb to /v1/heartbeat presenting certDER the way the proxy
// does: base64 DER in X-Agent-Cert, plus the proxy secret when withProxy.
func heartbeat(t *testing.T, base string, hb any, certDER []byte, withProxy bool) *http.Response {
	t.Helper()
	var raw []byte
	if b, ok := hb.([]byte); ok {
		raw = b
	} else {
		var err error
		if raw, err = json.Marshal(hb); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, base+"/v1/heartbeat", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if withProxy {
		req.Header.Set("X-Proxy-Auth", proxySecret)
	}
	if certDER != nil {
		req.Header.Set(api.AgentCertHeader, base64.StdEncoding.EncodeToString(certDER))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (e *env) heartbeat(t *testing.T, hb any, certDER []byte) *http.Response {
	t.Helper()
	return heartbeat(t, e.srv.URL, hb, certDER, true)
}

func hbBody(serverID, bootID string) api.Heartbeat {
	return api.Heartbeat{ServerID: serverID, AgentVersion: "0.0.2", BootID: bootID, UptimeSec: 42, SentAt: time.Now()}
}

func lastSeen(t *testing.T, e *env, serverID string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT last_seen_at FROM agents WHERE server_id = $1`, serverID).Scan(&at); err != nil {
		t.Fatalf("last_seen_at: %v", err)
	}
	return at
}

func TestHeartbeatUpdatesLastSeen(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	if lastSeen(t, e, id) != nil {
		t.Fatal("last_seen_at set before any heartbeat")
	}
	resp := e.heartbeat(t, hbBody(id, "boot-1"), certDER(t, out.CertPEM))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if at := lastSeen(t, e, id); at == nil || time.Since(*at) > time.Minute {
		t.Fatalf("last_seen_at = %v, want about now", at)
	}
}

func TestHeartbeatWithoutCertHeaderIsUnauthorised(t *testing.T) {
	e := newEnv(t)
	id, _ := enrolled(t, e)
	if resp := e.heartbeat(t, hbBody(id, "b"), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if resp := e.heartbeat(t, hbBody(id, "b"), []byte("not a certificate")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("garbage cert status = %d, want 401", resp.StatusCode)
	}
}

func signFor(t *testing.T, authority *ca.CA, serverID string, now time.Time) []byte {
	t.Helper()
	certPEM, err := authority.Sign(newCSR(t), serverID, hostTTL, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return certDER(t, certPEM)
}

const hostTTL = 90 * 24 * time.Hour

func TestHeartbeatWithForeignCertIsUnauthorised(t *testing.T) {
	e := newEnv(t)
	id, _ := enrolled(t, e)
	other, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	der := signFor(t, other, id, time.Now())
	if resp := e.heartbeat(t, hbBody(id, "b"), der); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHeartbeatWithExpiredCertIsUnauthorised(t *testing.T) {
	e := newEnv(t)
	id, _ := enrolled(t, e)
	der := signFor(t, e.ca, id, time.Now().Add(-2*hostTTL))
	if resp := e.heartbeat(t, hbBody(id, "b"), der); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHeartbeatBodyServerIDMustMatchCertificate(t *testing.T) {
	e := newEnv(t)
	idA, outA := enrolled(t, e)
	idB, _ := enrolled(t, e)
	resp := e.heartbeat(t, hbBody(idB, "b"), certDER(t, outA.CertPEM))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if countAudit(t, e, "agent.identity_mismatch", idA) != 1 {
		t.Fatal("agent.identity_mismatch not audited against the certificate's server")
	}
	if lastSeen(t, e, idB) != nil {
		t.Fatal("the spoofed server was touched")
	}
}

func TestHeartbeatFlagsChangedBootID(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	der := certDER(t, out.CertPEM)
	if resp := e.heartbeat(t, hbBody(id, "boot-1"), der); resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d", resp.StatusCode)
	}
	if countAudit(t, e, "agent.boot_id_changed", id) != 0 {
		t.Fatal("first heartbeat flagged as a boot change")
	}
	first := *lastSeen(t, e, id)
	if resp := e.heartbeat(t, hbBody(id, "boot-2"), der); resp.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want 200 (a reboot is a signal, not a rejection)", resp.StatusCode)
	}
	if countAudit(t, e, "agent.boot_id_changed", id) != 1 {
		t.Fatal("agent.boot_id_changed not audited")
	}
	if second := *lastSeen(t, e, id); !second.After(first) {
		t.Fatalf("last_seen_at not advanced: %v -> %v", first, second)
	}
}

func TestHeartbeatRejectsOversizedBody(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	body := []byte(`{"server_id":"` + id + `","boot_id":"` + strings.Repeat("a", 1<<20) + `"}`)
	if resp := e.heartbeat(t, body, certDER(t, out.CertPEM)); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestHeartbeatRateLimitPerServer(t *testing.T) {
	st := newEnv(t).st // reuse a migrated test database
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	frozen := time.Now()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(httpapi.NewAgentRouterAt(st, authority, proxySecret, lg, func() time.Time { return frozen }))
	t.Cleanup(srv.Close)
	e := &env{st: st, ca: authority, srv: srv}

	idA, outA := enrolled(t, e)
	idB, outB := enrolled(t, e)
	derA, derB := certDER(t, outA.CertPEM), certDER(t, outB.CertPEM)

	for i := 1; i <= 60; i++ {
		if resp := e.heartbeat(t, hbBody(idA, "b"), derA); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, resp.StatusCode)
		}
	}
	if resp := e.heartbeat(t, hbBody(idA, "b"), derA); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("61st status = %d, want 429", resp.StatusCode)
	}
	if resp := e.heartbeat(t, hbBody(idB, "b"), derB); resp.StatusCode != http.StatusOK {
		t.Fatalf("second server status = %d, want 200", resp.StatusCode)
	}
	frozen = frozen.Add(time.Minute)
	if resp := e.heartbeat(t, hbBody(idA, "b"), derA); resp.StatusCode != http.StatusOK {
		t.Fatalf("after a minute status = %d, want 200", resp.StatusCode)
	}
}

func TestHeartbeatResponseCarriesPollInterval(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	resp := e.heartbeat(t, hbBody(id, "b"), certDER(t, out.CertPEM))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var hr api.HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		t.Fatal(err)
	}
	if hr.PollIntervalSec != 30 {
		t.Fatalf("PollIntervalSec = %d, want 30", hr.PollIntervalSec)
	}
}

func TestAgentRouteRejectsMissingProxySecret(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	resp := heartbeat(t, e.srv.URL, hbBody(id, "b"), certDER(t, out.CertPEM), false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if lastSeen(t, e, id) != nil {
		t.Fatal("heartbeat accepted without the proxy secret")
	}
}

func TestAgentRouteRejectsWrongProxySecret(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/v1/heartbeat", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Proxy-Auth", "wrong")
	req.Header.Set(api.AgentCertHeader, base64.StdEncoding.EncodeToString(certDER(t, out.CertPEM)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if lastSeen(t, e, id) != nil {
		t.Fatal("heartbeat accepted with the wrong proxy secret")
	}
}

func TestHeartbeatRejectedForDecommissionedServer(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE servers SET decommissioned_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	resp := e.heartbeat(t, hbBody(id, "b"), certDER(t, out.CertPEM))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if countAudit(t, e, "agent.heartbeat_rejected", id) != 1 {
		t.Fatal("rejection not audited")
	}
	if lastSeen(t, e, id) != nil {
		t.Fatal("decommissioned server's last_seen_at updated")
	}
}

func TestHeartbeatRejectedForRevokedAgent(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE agents SET revoked_at = now() WHERE server_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	resp := e.heartbeat(t, hbBody(id, "b"), certDER(t, out.CertPEM))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if countAudit(t, e, "agent.heartbeat_rejected", id) != 1 {
		t.Fatal("rejection not audited")
	}
	if lastSeen(t, e, id) != nil {
		t.Fatal("revoked agent's last_seen_at updated")
	}
}

func TestHeartbeatRejectsSupersededCertificate(t *testing.T) {
	e := newEnv(t)
	id, first := enrolled(t, e)
	resp := e.post(t, "/v1/re-enrol", api.ReEnrolRequest{
		ServerID: id, EnrolKey: first.EnrolKey, CSRPEM: newCSR(t),
	}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-enrol status = %d", resp.StatusCode)
	}
	var second api.EnrolResponse
	if err := json.NewDecoder(resp.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}

	old := certDER(t, first.CertPEM)
	// The old certificate still chains to the CA and has not expired.
	if got, err := e.ca.Verify(old, time.Now()); err != nil || got != id {
		t.Fatalf("precondition: old certificate should still verify, got %q, %v", got, err)
	}
	if r := e.heartbeat(t, hbBody(id, "b"), old); r.StatusCode != http.StatusForbidden {
		t.Fatalf("superseded certificate status = %d, want 403", r.StatusCode)
	}
	if countAudit(t, e, "agent.cert_superseded", id) != 1 {
		t.Fatal("superseded certificate not audited")
	}
	if lastSeen(t, e, id) != nil {
		t.Fatal("superseded certificate updated last_seen_at")
	}
	if r := e.heartbeat(t, hbBody(id, "b"), certDER(t, second.CertPEM)); r.StatusCode != http.StatusOK {
		t.Fatalf("current certificate status = %d, want 200", r.StatusCode)
	}
}

func TestHeartbeatRejectsOversizedBootID(t *testing.T) {
	e := newEnv(t)
	id, out := enrolled(t, e)
	resp := e.heartbeat(t, hbBody(id, strings.Repeat("a", 1000)), certDER(t, out.CertPEM))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if lastSeen(t, e, id) != nil {
		t.Fatal("heartbeat with an oversized boot ID was recorded")
	}
}

// A certificate that chains to the CA but is no longer current must not be a
// way to write unbounded audit rows: the limiter runs before the pin.
func TestSupersededCertificateFloodIsRateLimitedBeforeAudit(t *testing.T) {
	st := newEnv(t).st
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(httpapi.NewAgentRouterAt(st, authority, proxySecret, lg, time.Now))
	t.Cleanup(srv.Close)
	e := &env{st: st, ca: authority, srv: srv}

	id, first := enrolled(t, e)
	if r := e.post(t, "/v1/re-enrol", api.ReEnrolRequest{ServerID: id, EnrolKey: first.EnrolKey, CSRPEM: newCSR(t)}, true); r.StatusCode != http.StatusOK {
		t.Fatalf("re-enrol status = %d", r.StatusCode)
	}
	old := certDER(t, first.CertPEM)

	var forbidden, limited int
	for i := 0; i < 100; i++ {
		switch e.heartbeat(t, hbBody(id, "b"), old).StatusCode {
		case http.StatusForbidden:
			forbidden++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatal("unexpected status for a superseded certificate")
		}
	}
	if limited == 0 || forbidden > 62 {
		t.Fatalf("forbidden = %d, limited = %d; the flood was not rate limited", forbidden, limited)
	}
	if n := countAudit(t, e, "agent.cert_superseded", id); n != forbidden {
		t.Fatalf("audit rows = %d, want one per 403 (%d) and none for 429s", n, forbidden)
	}
}
