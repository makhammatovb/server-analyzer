// Package httpapi holds the HTTP surface of the FleetGuard backend.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

// ProxyAuthHeader carries the shared secret the reverse proxy adds to every
// request it forwards.
const ProxyAuthHeader = "X-Proxy-Auth"

// RequireProxySecret rejects every request that does not carry the proxy
// secret, so a local process cannot bypass the reverse proxy. It panics on an
// empty secret: an empty value must never mean "no check required".
func RequireProxySecret(secret string) func(http.Handler) http.Handler {
	if secret == "" {
		panic("httpapi: RequireProxySecret called with an empty secret")
	}
	want := []byte(secret)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := []byte(r.Header.Get(ProxyAuthHeader))
			if subtle.ConstantTimeCompare(got, want) != 1 {
				writeError(w, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeError answers with a status and a generic body. The reason for a
// failure never reaches the caller; it goes to the logger and the audit log.
func writeError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": http.StatusText(status)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeBody reads a JSON body of at most api.MaxBodyBytes into v. It returns
// the status to answer with, or 0 on success.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, lg *slog.Logger) int {
	r.Body = http.MaxBytesReader(w, r.Body, api.MaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return http.StatusRequestEntityTooLarge
		}
		lg.Info("httpapi: undecodable request body", "path", r.URL.Path, "err", err)
		return http.StatusBadRequest
	}
	return 0
}
