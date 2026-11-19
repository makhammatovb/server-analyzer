package httpapi

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/store"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

// hostCertTTL is how long an issued host certificate stays valid.
const hostCertTTL = 90 * 24 * time.Hour

const auditActor = "agent"

type agentAPI struct {
	st  *store.Store
	ca  *ca.CA
	lg  *slog.Logger
	now func() time.Time
}

// NewAgentRouter serves the agent-facing API. Every /v1/* route requires the
// proxy secret. /v1/enrol and /v1/re-enrol deliberately require no client
// certificate: a first-time agent has none, and one whose certificate expired
// while its server was off must still be able to re-enrol. They are
// authenticated by the single-use token and the enrolment secret respectively.
func NewAgentRouter(st *store.Store, authority *ca.CA, proxySecret string, lg *slog.Logger) http.Handler {
	a := &agentAPI{st: st, ca: authority, lg: lg, now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enrol", a.enrol)
	mux.HandleFunc("POST /v1/re-enrol", a.reEnrol)
	return RequireProxySecret(proxySecret)(mux)
}

func (a *agentAPI) audit(r *http.Request, action, target string, detail any) {
	if err := a.st.AppendAudit(r.Context(), auditActor, action, target, detail); err != nil {
		a.lg.Error("httpapi: audit append failed", "action", action, "err", err)
	}
}

// signCert signs the CSR for serverID and returns the PEM certificate with its
// fingerprint and expiry.
func (a *agentAPI) signCert(csrPEM []byte, serverID string, now time.Time) (certPEM []byte, fingerprint string, notAfter time.Time, err error) {
	certPEM, err = a.ca.Sign(csrPEM, serverID, hostCertTTL, now)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, "", time.Time{}, errors.New("signed certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse signed certificate: %w", err)
	}
	return certPEM, a.ca.Fingerprint(block.Bytes), cert.NotAfter, nil
}

func (a *agentAPI) enrol(w http.ResponseWriter, r *http.Request) {
	var req api.EnrolRequest
	if status := decodeBody(w, r, &req, a.lg); status != 0 {
		writeError(w, status)
		return
	}
	if err := req.Validate(); err != nil {
		a.lg.Info("httpapi: invalid enrol request", "err", err)
		writeError(w, http.StatusBadRequest)
		return
	}
	now := a.now().UTC()

	serverID, err := a.st.ConsumeEnrolToken(r.Context(), req.Token, now)
	if errors.Is(err, store.ErrTokenInvalid) {
		// The store folds replayed, expired, unknown and decommissioned into
		// one error, so the audit entry cannot say which; the caller learns
		// less still. Never log the token itself.
		a.lg.Warn("httpapi: enrolment token rejected", "hostname", req.Hostname)
		a.audit(r, "agent.enrol_rejected", req.Hostname, map[string]string{"reason": "token invalid, expired, used or server decommissioned"})
		writeError(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: consume enrolment token", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}

	certPEM, fingerprint, notAfter, err := a.signCert(req.CSRPEM, serverID, now)
	if err != nil {
		// The token is already spent; an admin must issue a new one.
		a.lg.Warn("httpapi: signing enrolment CSR failed", "server_id", serverID, "err", err)
		a.audit(r, "agent.enrol_rejected", serverID, map[string]string{"reason": "csr rejected: " + err.Error()})
		writeError(w, http.StatusBadRequest)
		return
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		a.lg.Error("httpapi: generate enrolment secret", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	enrolKey := base64.RawURLEncoding.EncodeToString(secret)

	err = a.st.RecordEnrolment(r.Context(), store.Enrolment{
		ServerID:        serverID,
		Hostname:        req.Hostname,
		AgentVersion:    req.AgentVersion,
		CertFingerprint: fingerprint,
		EnrolKeyHash:    store.HashHighEntropySecret([]byte(enrolKey)),
		CertNotAfter:    notAfter,
	})
	if err != nil {
		a.lg.Error("httpapi: record enrolment", "server_id", serverID, "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	a.audit(r, "agent.enrolled", serverID, map[string]string{
		"hostname": req.Hostname, "agent_version": req.AgentVersion, "cert_fingerprint": fingerprint,
	})
	writeJSON(w, http.StatusOK, api.EnrolResponse{
		ServerID: serverID,
		CertPEM:  certPEM,
		CAPEM:    a.ca.CertPEM(),
		EnrolKey: enrolKey,
	})
}

func (a *agentAPI) reEnrol(w http.ResponseWriter, r *http.Request) {
	var req api.ReEnrolRequest
	if status := decodeBody(w, r, &req, a.lg); status != 0 {
		writeError(w, status)
		return
	}
	if err := req.Validate(); err != nil {
		a.lg.Info("httpapi: invalid re-enrol request", "err", err)
		writeError(w, http.StatusBadRequest)
		return
	}
	now := a.now().UTC()

	err := a.st.VerifyEnrolKey(r.Context(), req.ServerID, req.EnrolKey)
	if errors.Is(err, store.ErrEnrolKeyInvalid) {
		a.lg.Warn("httpapi: enrolment key rejected", "server_id", req.ServerID)
		a.audit(r, "agent.reenrol_rejected", req.ServerID, map[string]string{"reason": "enrolment key invalid, agent revoked or server decommissioned"})
		writeError(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: verify enrolment key", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}

	certPEM, fingerprint, _, err := a.signCert(req.CSRPEM, req.ServerID, now)
	if err != nil {
		a.lg.Warn("httpapi: signing re-enrolment CSR failed", "server_id", req.ServerID, "err", err)
		a.audit(r, "agent.reenrol_rejected", req.ServerID, map[string]string{"reason": "csr rejected: " + err.Error()})
		writeError(w, http.StatusBadRequest)
		return
	}
	a.audit(r, "agent.re-enrolled", req.ServerID, map[string]string{"cert_fingerprint": fingerprint})
	// The enrolment secret is unchanged and is not returned again.
	writeJSON(w, http.StatusOK, api.EnrolResponse{
		ServerID: req.ServerID,
		CertPEM:  certPEM,
		CAPEM:    a.ca.CertPEM(),
	})
}
