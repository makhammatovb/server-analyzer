package httpapi

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/makhammatovb/fleetguard/internal/server/store"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

// requireCurrentCert rejects a certificate that is not the one on record for
// its server. Chaining to the CA is not enough: re-enrolment overwrites the
// stored fingerprint but there is no CRL, so without this a superseded
// certificate would keep authenticating until it expires. It must run after
// AgentAuth.
func (a *agentAPI) requireCurrentCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, _ := ServerIDFrom(r.Context())
		presented := a.ca.Fingerprint(certDERFrom(r.Context()))
		stored, err := a.st.CertFingerprint(r.Context(), serverID)
		if errors.Is(err, store.ErrNotFound) {
			a.lg.Warn("httpapi: certificate for a server with no agent", "server_id", serverID)
			a.audit(r, "agent.auth_rejected", serverID, map[string]string{"reason": "no enrolled agent"})
			writeError(w, http.StatusForbidden)
			return
		}
		if err != nil {
			a.lg.Error("httpapi: read certificate fingerprint", "server_id", serverID, "err", err)
			writeError(w, http.StatusInternalServerError)
			return
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(stored)) != 1 {
			a.lg.Warn("httpapi: superseded certificate presented", "server_id", serverID)
			a.audit(r, "agent.cert_superseded", serverID, map[string]string{
				"reason":      "certificate is not the current one for this server",
				"fingerprint": presented,
			})
			writeError(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit applies the per-server limit. It must run after AgentAuth. Limited
// requests are logged, not audited, so a flood cannot fill the audit log.
func (a *agentAPI) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, _ := ServerIDFrom(r.Context())
		if !a.limiter.Allow(serverID, a.now()) {
			a.lg.Warn("httpapi: heartbeat rate limited", "server_id", serverID)
			writeError(w, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *agentAPI) heartbeat(w http.ResponseWriter, r *http.Request) {
	certServerID, _ := ServerIDFrom(r.Context())

	var hb api.Heartbeat
	if status := decodeBody(w, r, &hb, a.lg); status != 0 {
		writeError(w, status)
		return
	}
	if err := hb.Validate(); err != nil {
		a.lg.Info("httpapi: invalid heartbeat", "server_id", certServerID, "err", err)
		writeError(w, http.StatusBadRequest)
		return
	}
	if hb.ServerID != certServerID {
		a.lg.Warn("httpapi: heartbeat server ID differs from certificate", "server_id", certServerID)
		a.audit(r, "agent.identity_mismatch", certServerID, map[string]string{
			"reason": "heartbeat body names a different server than the certificate",
		})
		writeError(w, http.StatusForbidden)
		return
	}

	bootChanged, err := a.st.TouchHeartbeat(r.Context(), certServerID, hb.AgentVersion, hb.BootID, a.now().UTC())
	if errors.Is(err, store.ErrServerInactive) || errors.Is(err, store.ErrNotFound) {
		a.lg.Warn("httpapi: heartbeat from an inactive agent", "server_id", certServerID, "err", err)
		a.audit(r, "agent.heartbeat_rejected", certServerID, map[string]string{
			"reason": "agent revoked or server decommissioned",
		})
		writeError(w, http.StatusForbidden)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: touch heartbeat", "server_id", certServerID, "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	if bootChanged {
		// A signal, not a rejection: a rebooted server changes boot ID too.
		a.audit(r, "agent.boot_id_changed", certServerID, map[string]string{"boot_id": hb.BootID})
	}
	writeJSON(w, http.StatusOK, api.HeartbeatResponse{ConfigVersion: 1, PollIntervalSec: pollIntervalSec})
}
