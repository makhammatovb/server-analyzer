package httpapi_test

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

// AgentAuth is the whole gate: any route that uses it gets the pin and the
// limiter, with no way to compose them wrongly.
func TestAgentAuthEnforcesPinAndLimitWithoutTheRouter(t *testing.T) {
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const serverID = "7b0c2f0e-6d1a-4c53-9a63-1f2f4a1f9a10"
	der := signFor(t, authority, serverID, time.Now())
	current := authority.Fingerprint(der)

	stored := "someone-elses-fingerprint"
	lookup := func(context.Context, string) (string, error) { return stored, nil }
	var audited []string
	audit := func(_ *http.Request, action, _ string, _ any) { audited = append(audited, action) }
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	var reached int
	var gotID string
	h := httpapi.AgentAuth(authority, lookup, httpapi.NewRateLimiter(2), time.Now, audit, lg)(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached++
			gotID, _ = httpapi.ServerIDFrom(r.Context())
		}))
	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set(api.AgentCertHeader, base64.StdEncoding.EncodeToString(der))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(); code != http.StatusForbidden || reached != 0 {
		t.Fatalf("superseded: code %d, reached %d; want 403 and not reached", code, reached)
	}
	stored = current
	if code := do(); code != http.StatusOK || reached != 1 || gotID != serverID {
		t.Fatalf("current: code %d, reached %d, id %q", code, reached, gotID)
	}
	if code := do(); code != http.StatusTooManyRequests {
		t.Fatalf("third request code %d, want 429 (limit 2)", code)
	}
	if len(audited) != 1 || audited[0] != "agent.cert_superseded" {
		t.Fatalf("audited = %v, want exactly one agent.cert_superseded", audited)
	}
}
