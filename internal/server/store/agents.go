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
// enrolment for the same server.
func (s *Store) RecordEnrolment(ctx context.Context, e Enrolment) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO agents (server_id, hostname, agent_version, cert_fingerprint, cert_not_after, enrol_key_hash)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (server_id) DO UPDATE SET
		     hostname = EXCLUDED.hostname,
		     agent_version = EXCLUDED.agent_version,
		     cert_fingerprint = EXCLUDED.cert_fingerprint,
		     cert_not_after = EXCLUDED.cert_not_after,
		     enrol_key_hash = EXCLUDED.enrol_key_hash`,
		e.ServerID, e.Hostname, e.AgentVersion, e.CertFingerprint, e.CertNotAfter, e.EnrolKeyHash)
	if err != nil {
		return fmt.Errorf("store: record enrolment: %w", err)
	}
	return nil
}

// VerifyEnrolKey checks enrolKey against the stored hash in constant time.
func (s *Store) VerifyEnrolKey(ctx context.Context, serverID, enrolKey string) error {
	if _, err := uuid.Parse(serverID); err != nil {
		return ErrEnrolKeyInvalid
	}
	var stored []byte
	err := s.pool.QueryRow(ctx,
		`SELECT enrol_key_hash FROM agents WHERE server_id = $1`, serverID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEnrolKeyInvalid
	}
	if err != nil {
		return fmt.Errorf("store: verify enrolment key: %w", err)
	}
	if subtle.ConstantTimeCompare(stored, HashSecret(enrolKey)) != 1 {
		return ErrEnrolKeyInvalid
	}
	return nil
}

// TouchHeartbeat records a heartbeat and reports whether the boot ID differs
// from the stored one. A change is a signal, not a rejection: last_seen_at is
// always updated. An empty incoming or stored boot ID counts as unchanged, and
// an empty incoming one never overwrites the stored value.
func (s *Store) TouchHeartbeat(ctx context.Context, serverID, agentVersion, bootID string, at time.Time) (bool, error) {
	if _, err := uuid.Parse(serverID); err != nil {
		return false, ErrNotFound
	}
	var previous string
	err := s.pool.QueryRow(ctx,
		`WITH old AS (SELECT boot_id FROM agents WHERE server_id = $1 FOR UPDATE)
		 UPDATE agents
		    SET last_seen_at = $2,
		        agent_version = $3,
		        boot_id = CASE WHEN $4 = '' THEN agents.boot_id ELSE $4 END
		   FROM old
		  WHERE agents.server_id = $1
		  RETURNING old.boot_id`,
		serverID, at, agentVersion, bootID).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("store: touch heartbeat: %w", err)
	}
	return previous != "" && bootID != "" && previous != bootID, nil
}
