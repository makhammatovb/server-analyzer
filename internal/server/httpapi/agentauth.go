package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/store"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

type ctxKey int

const serverIDKey ctxKey = iota

// ServerIDFrom returns the server ID AgentAuth established for the request.
func ServerIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(serverIDKey).(string)
	return id, ok && id != ""
}

// FingerprintLookup returns the fingerprint of the certificate currently on
// record for a server, or an error wrapping store.ErrNotFound.
type FingerprintLookup func(ctx context.Context, serverID string) (string, error)

// AuditFunc records an audit entry for a rejected request.
type AuditFunc func(r *http.Request, action, target string, detail any)

// AgentAuth is the complete gate for an agent-authenticated route. It runs, in
// this order:
//
//  1. Chain: the base64 DER certificate in api.AgentCertHeader must be issued
//     by our CA and in date (401 otherwise). This establishes the server ID
//     and proves nothing about possession of the private key: that was proven
//     by the TLS handshake at the reverse proxy, and is trustworthy only
//     because RequireProxySecret wraps the route and the backend is loopback.
//  2. Limit: limiter, keyed by that server ID (429 otherwise).
//  3. Pin: the certificate's fingerprint must equal the stored one (403 and
//     an audit entry otherwise). Re-enrolment overwrites the stored value and
//     there is no CRL, so without this a superseded certificate would keep
//     authenticating until it expires.
//
// The pin costs a database read and writes an audit row per rejection, so it
// must sit behind the limiter; the limiter needs a server ID, so it must sit
// behind the chain check.
func AgentAuth(authority *ca.CA, lookup FingerprintLookup, limiter *RateLimiter, now func() time.Time, audit AuditFunc, lg *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			der, err := base64.StdEncoding.DecodeString(r.Header.Get(api.AgentCertHeader))
			if err != nil || len(der) == 0 {
				writeError(w, http.StatusUnauthorized)
				return
			}
			serverID, err := authority.Verify(der, now())
			if err != nil {
				writeError(w, http.StatusUnauthorized)
				return
			}

			if !limiter.Allow(serverID, now()) {
				lg.Warn("httpapi: agent rate limited", "server_id", serverID)
				writeError(w, http.StatusTooManyRequests)
				return
			}

			presented := authority.Fingerprint(der)
			stored, err := lookup(r.Context(), serverID)
			if errors.Is(err, store.ErrNotFound) {
				lg.Warn("httpapi: certificate for a server with no agent", "server_id", serverID)
				audit(r, "agent.auth_rejected", serverID, map[string]string{"reason": "no enrolled agent"})
				writeError(w, http.StatusForbidden)
				return
			}
			if err != nil {
				lg.Error("httpapi: read certificate fingerprint", "server_id", serverID, "err", err)
				writeError(w, http.StatusInternalServerError)
				return
			}
			if subtle.ConstantTimeCompare([]byte(presented), []byte(stored)) != 1 {
				lg.Warn("httpapi: superseded certificate presented", "server_id", serverID)
				audit(r, "agent.cert_superseded", serverID, map[string]string{
					"reason":      "certificate is not the current one for this server",
					"fingerprint": presented,
				})
				writeError(w, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), serverIDKey, serverID)))
		})
	}
}
