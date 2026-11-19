package httpapi

import (
	"errors"
	"net/http"

	"github.com/makhammatovb/fleetguard/internal/server/store"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

func (a *agentAPI) heartbeat(w http.ResponseWriter, r *http.Request) {
	certServerID, ok := ServerIDFrom(r.Context())
	if !ok {
		// AgentAuth always sets it; failing loudly beats an empty audit target.
		a.lg.Error("httpapi: heartbeat reached without an authenticated server ID")
		writeError(w, http.StatusInternalServerError)
		return
	}

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
