package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

type ctxKey int

const (
	serverIDKey ctxKey = iota
	certDERKey
)

// ServerIDFrom returns the server ID AgentAuth established for the request.
func ServerIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(serverIDKey).(string)
	return id, ok && id != ""
}

func certDERFrom(ctx context.Context) []byte {
	der, _ := ctx.Value(certDERKey).([]byte)
	return der
}

// AgentAuth authenticates the agent from the base64 DER certificate in the
// api.AgentCertHeader header and puts its server ID in the request context.
//
// It proves only that the certificate was issued by our CA and is in date. It
// does not prove the caller holds the private key: that was proven by the TLS
// handshake the reverse proxy performed, and is trustworthy only because
// RequireProxySecret wraps the route and the backend listens on loopback. It
// also does not prove the certificate is the current one; the router checks
// that against the stored fingerprint. Failures answer a bare 401.
func AgentAuth(authority *ca.CA, now func() time.Time) func(http.Handler) http.Handler {
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
			ctx := context.WithValue(r.Context(), serverIDKey, serverID)
			ctx = context.WithValue(ctx, certDERKey, der)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
