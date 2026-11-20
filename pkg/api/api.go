// Package api defines the wire types exchanged between the FleetGuard agent
// and server.
package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	// MaxBodyBytes is the largest request body the server will read.
	MaxBodyBytes = 64 * 1024
	// AgentCertHeader carries the client certificate when TLS is terminated
	// by a proxy in front of the server.
	AgentCertHeader = "X-Agent-Cert"
)

// EnrolRequest is sent by an agent presenting a one-time enrolment token.
type EnrolRequest struct {
	Token        string `json:"token"`
	CSRPEM       []byte `json:"csr_pem"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

// EnrolResponse returns the issued identity to a newly enrolled agent.
type EnrolResponse struct {
	ServerID string `json:"server_id"`
	CertPEM  []byte `json:"cert_pem"`
	CAPEM    []byte `json:"ca_pem"`
	EnrolKey string `json:"enrol_key,omitempty"`
}

// ReEnrolRequest asks for a fresh certificate for an already enrolled agent.
type ReEnrolRequest struct {
	ServerID string `json:"server_id"`
	EnrolKey string `json:"enrol_key,omitempty"`
	CSRPEM   []byte `json:"csr_pem"`
}

// Heartbeat is the periodic liveness report from an agent.
type Heartbeat struct {
	ServerID     string    `json:"server_id"`
	AgentVersion string    `json:"agent_version"`
	BootID       string    `json:"boot_id"`
	UptimeSec    int64     `json:"uptime_sec"`
	SentAt       time.Time `json:"sent_at"`
}

// HeartbeatResponse tells the agent the current server-side configuration.
type HeartbeatResponse struct {
	ConfigVersion   int `json:"config_version"`
	PollIntervalSec int `json:"poll_interval_sec"`
}

// Validate reports the first missing required field.
func (r EnrolRequest) Validate() error {
	switch {
	case r.Token == "":
		return errors.New("field Token is required")
	case len(r.CSRPEM) == 0:
		return errors.New("field CSRPEM is required")
	}
	return validateHostname(r.Hostname)
}

// maxHostnameBytes is the DNS name limit.
const maxHostnameBytes = 253

// validateHostname bounds the hostname and restricts it to the characters a
// DNS name can contain, so it is safe to store and log.
func validateHostname(h string) error {
	if h == "" {
		return errors.New("field Hostname is required")
	}
	if len(h) > maxHostnameBytes {
		return fmt.Errorf("field Hostname exceeds %d bytes", maxHostnameBytes)
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		if !ok {
			return errors.New("field Hostname contains characters outside [A-Za-z0-9._-]")
		}
	}
	return nil
}

// Validate reports the first missing or malformed field.
func (r ReEnrolRequest) Validate() error {
	if err := validateUUID("ServerID", r.ServerID); err != nil {
		return err
	}
	switch {
	case r.EnrolKey == "":
		return errors.New("field EnrolKey is required")
	case len(r.CSRPEM) == 0:
		return errors.New("field CSRPEM is required")
	}
	return nil
}

// Validate reports a missing or malformed ServerID.
func (h Heartbeat) Validate() error {
	if err := validateUUID("ServerID", h.ServerID); err != nil {
		return err
	}
	if err := validateToken("BootID", h.BootID); err != nil {
		return err
	}
	return validateToken("AgentVersion", h.AgentVersion)
}

// maxTokenBytes bounds BootID and AgentVersion, which are stored and audited.
const maxTokenBytes = 64

// validateToken bounds an optional identifier-like field and restricts it to
// a conservative charset (UUIDs, kernel boot IDs and semver all fit), so it is
// safe to store and log. An empty value is allowed.
func validateToken(field, v string) error {
	if len(v) > maxTokenBytes {
		return fmt.Errorf("field %s exceeds %d bytes", field, maxTokenBytes)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '+' || c == ':'
		if !ok {
			return fmt.Errorf("field %s contains characters outside [A-Za-z0-9._:+-]", field)
		}
	}
	return nil
}

func validateUUID(field, v string) error {
	if v == "" {
		return fmt.Errorf("field %s is required", field)
	}
	if _, err := uuid.Parse(v); err != nil {
		return fmt.Errorf("field %s is not a valid UUID", field)
	}
	return nil
}
