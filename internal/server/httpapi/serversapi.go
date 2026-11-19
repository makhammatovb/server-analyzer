package httpapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/makhammatovb/fleetguard/internal/server/store"
)

const (
	// enrolTokenTTL is how long an enrolment token stays redeemable.
	enrolTokenTTL = time.Hour

	maxServerNameLen = 128
	maxServerNoteLen = 1024
)

type serverDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// fleetDTO is one row of the fleet list. A decommissioned server does not
// appear in the list at all; it has no state to show.
type fleetDTO struct {
	serverDTO
	LastSeenAt   *time.Time `json:"last_seen_at"`
	AgentVersion string     `json:"agent_version"`
	Online       bool       `json:"online"`
	CertNotAfter *time.Time `json:"cert_not_after"`
}

type enrolTokenDTO struct {
	InstallCommand string    `json:"install_command"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// registerServerRoutes adds the server-management routes to the admin mux.
func (a *authAPI) registerServerRoutes(mux *http.ServeMux, requireUser func(http.Handler) http.Handler) {
	mux.Handle("POST /api/servers", requireUser(RequireAdmin(http.HandlerFunc(a.createServer))))
	mux.Handle("GET /api/servers", requireUser(http.HandlerFunc(a.listServers)))
	mux.Handle("GET /api/servers/{id}", requireUser(http.HandlerFunc(a.getServer)))
	mux.Handle("POST /api/servers/{id}/enrol-token", requireUser(RequireAdmin(http.HandlerFunc(a.reissueEnrolToken))))
	mux.Handle("POST /api/servers/{id}/decommission", requireUser(RequireAdmin(http.HandlerFunc(a.decommission))))
}

// installCommand renders the one-liner an admin runs on the new server. The
// installer is fetched from the dashboard origin, but the agent is pointed at
// the agent origin, whose certificate it can verify. The token is base64url, so it needs no shell quoting.
func (a *authAPI) installCommand(token string) string {
	return fmt.Sprintf("curl -sSL %s/install.sh | sudo bash -s -- --token=%s --server-url=%s", a.origin, token, a.agentOrigin)
}

// issueToken mints a single-use token for serverID and audits that it was
// issued. The token itself never reaches the audit log or the logger.
func (a *authAPI) issueToken(r *http.Request, actorID, serverID string) (enrolTokenDTO, error) {
	now := a.now().UTC()
	token, err := a.st.CreateEnrolToken(r.Context(), serverID, enrolTokenTTL, now)
	if err != nil {
		return enrolTokenDTO{}, err
	}
	if err := a.st.AppendAudit(r.Context(), actorID, "server.enrol_token_issued", serverID, nil); err != nil {
		a.lg.Error("httpapi: audit append failed", "action", "server.enrol_token_issued", "err", err)
	}
	return enrolTokenDTO{InstallCommand: a.installCommand(token), TokenExpiresAt: now.Add(enrolTokenTTL)}, nil
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (a *authAPI) createServer(w http.ResponseWriter, r *http.Request) {
	admin, _ := UserFromContext(r.Context())
	var body struct {
		Name string `json:"name"`
		Note string `json:"note"`
	}
	if status := decodeBody(w, r, &body, a.lg); status != 0 {
		writeError(w, status)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || utf8.RuneCountInString(name) > maxServerNameLen || utf8.RuneCountInString(body.Note) > maxServerNoteLen {
		writeError(w, http.StatusBadRequest)
		return
	}
	srv, err := a.st.CreateServer(r.Context(), name, body.Note)
	if errors.Is(err, store.ErrNameTaken) {
		a.lg.Info("httpapi: server name already taken", "admin_id", admin.ID)
		writeError(w, http.StatusConflict)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: create server failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	if err := a.st.AppendAudit(r.Context(), admin.ID, "server.created", srv.ID, map[string]string{"name": srv.Name}); err != nil {
		a.lg.Error("httpapi: audit append failed", "action", "server.created", "err", err)
	}
	tok, err := a.issueToken(r, admin.ID, srv.ID)
	if err != nil {
		// The server exists; an admin can issue its token with enrol-token.
		a.lg.Error("httpapi: issue enrolment token failed", "server_id", srv.ID, "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, http.StatusCreated, struct {
		Server serverDTO `json:"server"`
		enrolTokenDTO
	}{serverDTO{ID: srv.ID, Name: srv.Name, Note: srv.Note, CreatedAt: srv.CreatedAt}, tok})
}

func toFleetDTO(s store.ServerStatus) fleetDTO {
	return fleetDTO{
		serverDTO:    serverDTO{ID: s.ID, Name: s.Name, Note: s.Note, CreatedAt: s.CreatedAt},
		LastSeenAt:   s.LastSeenAt,
		AgentVersion: s.AgentVersion,
		Online:       s.Online,
		CertNotAfter: s.CertNotAfter,
	}
}

func (a *authAPI) listServers(w http.ResponseWriter, r *http.Request) {
	rows, err := a.st.ListServersWithStatus(r.Context(), a.now())
	if err != nil {
		a.lg.Error("httpapi: list servers failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	out := make([]fleetDTO, 0, len(rows))
	for _, s := range rows {
		out = append(out, toFleetDTO(s))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *authAPI) getServer(w http.ResponseWriter, r *http.Request) {
	// The fleet list is small and already excludes decommissioned servers, so
	// filtering it keeps "visible" defined in exactly one place.
	rows, err := a.st.ListServersWithStatus(r.Context(), a.now())
	if err != nil {
		a.lg.Error("httpapi: get server failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	for _, s := range rows {
		if s.ID == id {
			writeJSON(w, http.StatusOK, toFleetDTO(s))
			return
		}
	}
	writeError(w, http.StatusNotFound)
}

func (a *authAPI) reissueEnrolToken(w http.ResponseWriter, r *http.Request) {
	admin, _ := UserFromContext(r.Context())
	srv, err := a.st.GetServer(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && srv.DecommissionedAt != nil) {
		writeError(w, http.StatusNotFound)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: get server failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	tok, err := a.issueToken(r, admin.ID, srv.ID)
	if err != nil {
		a.lg.Error("httpapi: issue enrolment token failed", "server_id", srv.ID, "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, tok)
}

func (a *authAPI) decommission(w http.ResponseWriter, r *http.Request) {
	admin, _ := UserFromContext(r.Context())
	err := a.st.DecommissionServer(r.Context(), r.PathValue("id"), admin.ID, a.now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: decommission failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CheckListenAddr refuses a listen address that is not loopback unless
// allowPublic is set. The reverse proxy is meant to be the only public
// listener: the proxy secret and the client-certificate header model both
// assume nothing else can reach this backend, so the rule is enforced here and
// not left to documentation. A hostname must resolve only to loopback
// addresses; an empty host (":8080") means every interface and is refused.
func CheckListenAddr(addr string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if allowPublic {
		return nil
	}
	if host == "" {
		return fmt.Errorf("listen address %q binds every interface; use a loopback address or set FG_ALLOW_PUBLIC_LISTEN=1", addr)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("listen address %q: cannot resolve %q: %v", addr, host, err)
	}
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok || !a.Unmap().IsLoopback() {
			return fmt.Errorf("listen address %q resolves to non-loopback %s; use a loopback address or set FG_ALLOW_PUBLIC_LISTEN=1", addr, ip)
		}
	}
	return nil
}
