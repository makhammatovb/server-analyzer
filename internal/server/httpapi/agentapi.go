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

// unknownTarget is the audit target for a rejected enrolment: no server has
// been identified, and caller-supplied text must not become a target, which is
// otherwise always a server ID.
const unknownTarget = "unknown"

// heartbeatsPerMinute is the per-server rate limit: generous against the
// 2/min an agent actually sends.
const heartbeatsPerMinute = 60

// enrolPerMinute is the per-address budget shared by /v1/enrol and
// /v1/re-enrol. A real enrolment is one request, and an admin enrols one server
// at a time; ten (also the burst) leaves room for installer retries and a few
// servers behind one NAT address, while capping a hostile address at ten
// signature checks, database writes and audit rows a minute.
const enrolPerMinute = 10

// pollIntervalSec is how often agents are told to heartbeat.
const pollIntervalSec = 30

type agentAPI struct {
	st      *store.Store
	ca      *ca.CA
	lg      *slog.Logger
	now     func() time.Time
	limiter *RateLimiter
	// enrolLimiter limits the certificate-less routes by client address.
	enrolLimiter *RateLimiter
	proxySecret  string
}

// NewAgentRouter serves the agent-facing API. Every /v1/* route requires the
// proxy secret. /v1/enrol and /v1/re-enrol deliberately require no client
// certificate: a first-time agent has none, and one whose certificate expired
// while its server was off must still be able to re-enrol. They are
// authenticated by the single-use token and the enrolment secret respectively,
// and, having no certificate to key a limiter on, are limited per client
// address.
func NewAgentRouter(st *store.Store, authority *ca.CA, proxySecret string, lg *slog.Logger) http.Handler {
	return NewAgentRouterAt(st, authority, proxySecret, lg, time.Now)
}

// NewAgentRouterAt is NewAgentRouter with an injectable clock.
//
// /v1/heartbeat additionally requires a client certificate (AgentAuth), that
// certificate to be the one currently on record, and stays within the
// per-server rate limit.
func NewAgentRouterAt(st *store.Store, authority *ca.CA, proxySecret string, lg *slog.Logger, now func() time.Time) http.Handler {
	a := &agentAPI{st: st, ca: authority, lg: lg, now: now, limiter: NewRateLimiter(heartbeatsPerMinute),
		enrolLimiter: NewRateLimiter(enrolPerMinute), proxySecret: proxySecret}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enrol", a.limitByAddress(a.enrol))
	mux.HandleFunc("POST /v1/re-enrol", a.limitByAddress(a.reEnrol))
	agentAuth := AgentAuth(authority, st.CertFingerprint, a.limiter, now, a.audit, lg)
	mux.Handle("POST /v1/heartbeat", agentAuth(http.HandlerFunc(a.heartbeat)))
	return RequireProxySecret(proxySecret)(mux)
}

// limitByAddress rate-limits a route that needs no certificate by client
// address, before the handler's signature check, database write and audit row.
// A limited request is deliberately not audited: writing a row per flooded
// request is the amplification this exists to prevent. Both enrolment routes
// share one budget per address, so alternating between them gains nothing.
func (a *agentAPI) limitByAddress(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, a.proxySecret)
		if !a.enrolLimiter.Allow(ip, a.now()) {
			a.lg.Warn("httpapi: enrolment rate limited", "ip", ip, "path", r.URL.Path)
			writeError(w, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (a *agentAPI) audit(r *http.Request, action, target string, detail any) {
	if err := a.st.AppendAudit(r.Context(), a.now(), auditActor, action, target, detail); err != nil {
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
	if _, err := ca.CheckCSR(req.CSRPEM); err != nil {
		a.lg.Info("httpapi: invalid enrol CSR", "hostname", req.Hostname, "err", err)
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
		a.audit(r, "agent.enrol_rejected", unknownTarget, map[string]string{
			"reason":   "token invalid, expired, used or server decommissioned",
			"hostname": req.Hostname, // already bounded by Validate
		})
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
		// Only exceptional failures reach here (checkCSR passed); the token is
		// spent, so an admin issues a new one.
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
	if _, err := ca.CheckCSR(req.CSRPEM); err != nil {
		a.lg.Info("httpapi: invalid re-enrol CSR", "server_id", req.ServerID, "err", err)
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

	certPEM, fingerprint, notAfter, err := a.signCert(req.CSRPEM, req.ServerID, now)
	if err != nil {
		a.lg.Warn("httpapi: signing re-enrolment CSR failed", "server_id", req.ServerID, "err", err)
		a.audit(r, "agent.reenrol_rejected", req.ServerID, map[string]string{"reason": "csr rejected: " + err.Error()})
		writeError(w, http.StatusBadRequest)
		return
	}
	err = a.st.RecordCertRotation(r.Context(), req.ServerID, fingerprint, notAfter)
	if errors.Is(err, store.ErrServerInactive) || errors.Is(err, store.ErrNotFound) {
		// Revoked or decommissioned between the key check and now.
		a.lg.Warn("httpapi: cert rotation refused", "server_id", req.ServerID, "err", err)
		a.audit(r, "agent.reenrol_rejected", req.ServerID, map[string]string{"reason": "agent revoked or server decommissioned"})
		writeError(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: record cert rotation", "server_id", req.ServerID, "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	a.audit(r, "agent.reenrolled", req.ServerID, map[string]string{"cert_fingerprint": fingerprint})
	// The enrolment secret is unchanged and is not returned again.
	writeJSON(w, http.StatusOK, api.EnrolResponse{
		ServerID: req.ServerID,
		CertPEM:  certPEM,
		CAPEM:    a.ca.CertPEM(),
	})
}
