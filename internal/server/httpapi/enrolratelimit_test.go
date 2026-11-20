package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

// postFrom posts body to path as the reverse proxy would for a client at ip:
// the proxy secret plus X-Real-IP.
func (e *env) postFrom(t *testing.T, ip, path string, body any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Proxy-Auth", proxySecret)
	req.Header.Set("X-Real-IP", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func countAuditByHostname(t *testing.T, e *env, action, hostname string) int {
	t.Helper()
	var n int
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = $1 AND detail->>'hostname' = $2`, action, hostname).Scan(&n)
	if err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// A flood of failing enrolments from one address is cut off, the cut-off
// requests write no audit rows, and another address is unaffected. The clock is
// frozen so the bucket cannot refill mid-test.
func TestEnrolIsRateLimitedPerAddressAndLimitedRequestsAreNotAudited(t *testing.T) {
	frozen := time.Now()
	e := newEnvAt(t, func() time.Time { return frozen })
	host := "flood-" + uuid.NewString()
	enrolBody := func() api.EnrolRequest {
		return api.EnrolRequest{Token: "bogus-" + uuid.NewString(), CSRPEM: newCSR(t), Hostname: host, AgentVersion: "0.0.1"}
	}

	rejected, limited := 0, 0
	for range 60 {
		switch got := e.postFrom(t, "203.0.113.7", "/v1/enrol", enrolBody()); got {
		case http.StatusUnauthorized:
			if limited > 0 {
				t.Fatal("a 401 after the limit was reached")
			}
			rejected++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("status = %d", got)
		}
	}
	if limited == 0 || rejected == 0 || rejected > 20 {
		t.Fatalf("rejected=%d limited=%d, want a small burst then 429s", rejected, limited)
	}
	if got := countAuditByHostname(t, e, "agent.enrol_rejected", host); got != rejected {
		t.Fatalf("audit rows = %d, want %d (one per processed request, none for the %d limited)", got, rejected, limited)
	}

	// The same address is limited on /v1/re-enrol as well: one budget per address.
	reTarget := uuid.NewString()
	if got := e.postFrom(t, "203.0.113.7", "/v1/re-enrol", api.ReEnrolRequest{ServerID: reTarget, EnrolKey: "x", CSRPEM: newCSR(t)}); got != http.StatusTooManyRequests {
		t.Fatalf("re-enrol from a limited address = %d, want 429", got)
	}
	if n := countAudit(t, e, "agent.reenrol_rejected", reTarget); n != 0 {
		t.Fatalf("limited re-enrol wrote %d audit rows", n)
	}

	// A different address has its own budget.
	if got := e.postFrom(t, "198.51.100.9", "/v1/enrol", enrolBody()); got != http.StatusUnauthorized {
		t.Fatalf("second address = %d, want 401 (processed, not limited)", got)
	}
}

func TestReEnrolFloodWritesBoundedAuditRows(t *testing.T) {
	frozen := time.Now()
	e := newEnvAt(t, func() time.Time { return frozen })
	target := uuid.NewString()
	for range 60 {
		e.postFrom(t, "203.0.113.50", "/v1/re-enrol", api.ReEnrolRequest{ServerID: target, EnrolKey: "x", CSRPEM: newCSR(t)})
	}
	if n := countAudit(t, e, "agent.reenrol_rejected", target); n == 0 || n > 20 {
		t.Fatalf("reenrol_rejected rows = %d for a 60-request flood, want a small bounded number", n)
	}
}

// Audit rows carry the router's injected clock, so they agree with last_seen_at
// and a frozen-clock test can assert ordering.
func TestAgentAuditRowsUseTheInjectedClock(t *testing.T) {
	frozen := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	e := newEnvAt(t, func() time.Time { return frozen })
	host := "clock-" + uuid.NewString()
	e.postFrom(t, "203.0.113.77", "/v1/enrol", api.EnrolRequest{Token: "bogus", CSRPEM: newCSR(t), Hostname: host, AgentVersion: "0.0.1"})

	var at time.Time
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT at FROM audit_log WHERE action = 'agent.enrol_rejected' AND detail->>'hostname' = $1`, host).Scan(&at); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !at.Equal(frozen) {
		t.Fatalf("audit at = %v, want the injected clock %v", at, frozen)
	}
}
