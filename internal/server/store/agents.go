package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrEnrolKeyInvalid is returned when an enrolment key does not match the one
// recorded for the server, or the server has no enrolled agent.
var ErrEnrolKeyInvalid = errors.New("store: enrolment key invalid")

// ErrServerInactive is returned when the agent is revoked or its server is
// decommissioned. It is distinguishable so callers can audit the real reason;
// agent-facing handlers must still answer 401, not 403, so a caller cannot tell
// a retired server from an unknown one.
var ErrServerInactive = errors.New("store: agent revoked or server decommissioned")

// Enrolment is the record written when an agent enrols.
type Enrolment struct {
	ServerID        string
	Hostname        string
	AgentVersion    string
	CertFingerprint string
	EnrolKeyHash    []byte
	CertNotAfter    time.Time
}

// RecordEnrolment stores the agent for a server, replacing any previous
// enrolment for the same server. A fresh enrolment clears any revocation.
func (s *Store) RecordEnrolment(ctx context.Context, e Enrolment) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO agents (server_id, hostname, agent_version, cert_fingerprint, cert_not_after, enrol_key_hash)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (server_id) DO UPDATE SET
		     hostname = EXCLUDED.hostname,
		     agent_version = EXCLUDED.agent_version,
		     cert_fingerprint = EXCLUDED.cert_fingerprint,
		     cert_not_after = EXCLUDED.cert_not_after,
		     enrol_key_hash = EXCLUDED.enrol_key_hash,
		     revoked_at = NULL`,
		e.ServerID, e.Hostname, e.AgentVersion, e.CertFingerprint, e.CertNotAfter, e.EnrolKeyHash)
	if err != nil {
		return fmt.Errorf("store: record enrolment: %w", err)
	}
	return nil
}

// VerifyEnrolKey checks enrolKey against the stored hash in constant time. A
// revoked agent or decommissioned server is refused with ErrEnrolKeyInvalid.
func (s *Store) VerifyEnrolKey(ctx context.Context, serverID, enrolKey string) error {
	if _, err := uuid.Parse(serverID); err != nil {
		return ErrEnrolKeyInvalid
	}
	var stored []byte
	err := s.pool.QueryRow(ctx,
		`SELECT a.enrol_key_hash FROM agents a
		   JOIN servers s ON s.id = a.server_id
		  WHERE a.server_id = $1 AND a.revoked_at IS NULL AND s.decommissioned_at IS NULL`, serverID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEnrolKeyInvalid
	}
	if err != nil {
		return fmt.Errorf("store: verify enrolment key: %w", err)
	}
	if subtle.ConstantTimeCompare(stored, HashHighEntropySecret([]byte(enrolKey))) != 1 {
		return ErrEnrolKeyInvalid
	}
	return nil
}

// TouchHeartbeat records a heartbeat and reports whether the boot ID differs
// from the stored one. A change is a signal, not a rejection: last_seen_at is
// always updated. A revoked agent or decommissioned server is refused with
// ErrServerInactive. An empty incoming or stored boot ID counts as unchanged, and
// an empty incoming boot ID or version never overwrites the stored value.
func (s *Store) TouchHeartbeat(ctx context.Context, serverID, agentVersion, bootID string, at time.Time) (bool, error) {
	if _, err := uuid.Parse(serverID); err != nil {
		return false, ErrNotFound
	}
	var previous string
	err := s.pool.QueryRow(ctx,
		`WITH old AS (
		     SELECT a.boot_id FROM agents a
		       JOIN servers s ON s.id = a.server_id
		      WHERE a.server_id = $1 AND a.revoked_at IS NULL AND s.decommissioned_at IS NULL
		        FOR UPDATE OF a)
		 UPDATE agents
		    SET last_seen_at = $2,
		        agent_version = CASE WHEN $3 = '' THEN agents.agent_version ELSE $3 END,
		        boot_id = CASE WHEN $4 = '' THEN agents.boot_id ELSE $4 END
		   FROM old
		  WHERE agents.server_id = $1
		  RETURNING old.boot_id`,
		serverID, at, agentVersion, bootID).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		// Failure path only: tell an inactive agent apart from an unknown one.
		var exists bool
		if qerr := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM agents WHERE server_id = $1)`, serverID).Scan(&exists); qerr != nil {
			return false, fmt.Errorf("store: touch heartbeat: %w", qerr)
		}
		if exists {
			return false, ErrServerInactive
		}
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("store: touch heartbeat: %w", err)
	}
	return previous != "" && bootID != "" && previous != bootID, nil
}

// RecordCertRotation stores the fingerprint and expiry of a freshly issued
// certificate for an already enrolled agent, leaving every other column alone.
// It returns ErrNotFound when the server has no agent row, and ErrServerInactive
// for a revoked agent or decommissioned server, which must not be rotated.
func (s *Store) RecordCertRotation(ctx context.Context, serverID, certFingerprint string, notAfter time.Time) error {
	if _, err := uuid.Parse(serverID); err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE agents a SET cert_fingerprint = $2, cert_not_after = $3
		   FROM servers s
		  WHERE s.id = a.server_id AND a.server_id = $1
		    AND a.revoked_at IS NULL AND s.decommissioned_at IS NULL`,
		serverID, certFingerprint, notAfter)
	if err != nil {
		return fmt.Errorf("store: record cert rotation: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM agents WHERE server_id = $1)`, serverID).Scan(&exists); err != nil {
		return fmt.Errorf("store: record cert rotation: %w", err)
	}
	if exists {
		return ErrServerInactive
	}
	return ErrNotFound
}
