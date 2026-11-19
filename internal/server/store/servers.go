package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrNotFound is returned when a requested row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrNameTaken is returned when a server name is already in use.
	ErrNameTaken = errors.New("store: server name already taken")
	// ErrTokenInvalid is returned for an unknown, expired or already-consumed
	// enrolment token alike, so callers probing tokens learn nothing.
	ErrTokenInvalid = errors.New("store: enrolment token invalid")
)

// onlineWindow is the agent-silence threshold after which a server is offline.
const onlineWindow = 180 * time.Second

// Server is a registered server.
type Server struct {
	ID        string
	Name      string
	Note      string
	CreatedAt time.Time
}

// ServerStatus is a server together with the state of its agent.
type ServerStatus struct {
	Server
	LastSeenAt   *time.Time
	AgentVersion string
	Online       bool
	CertNotAfter *time.Time
}

// HashSecret returns the SHA-256 of a high-entropy secret (enrolment token or
// enrolment key). Callers building an Enrolment use it for EnrolKeyHash.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// CreateServer registers a server. It returns ErrNameTaken if the name exists.
func (s *Store) CreateServer(ctx context.Context, name, note string) (Server, error) {
	srv := Server{ID: uuid.NewString(), Name: name, Note: note, CreatedAt: time.Now().UTC()}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO servers (id, name, note, created_at) VALUES ($1, $2, $3, $4)`,
		srv.ID, srv.Name, srv.Note, srv.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Server{}, ErrNameTaken
		}
		return Server{}, fmt.Errorf("store: create server: %w", err)
	}
	return srv, nil
}

// GetServer returns the server with the given ID, or ErrNotFound.
func (s *Store) GetServer(ctx context.Context, id string) (Server, error) {
	if _, err := uuid.Parse(id); err != nil {
		return Server{}, ErrNotFound
	}
	var srv Server
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, name, note, created_at FROM servers WHERE id = $1`, id).
		Scan(&srv.ID, &srv.Name, &srv.Note, &srv.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	if err != nil {
		return Server{}, fmt.Errorf("store: get server: %w", err)
	}
	return srv, nil
}

// ListServersWithStatus returns every non-decommissioned server with its agent
// state. A server is Online when its last heartbeat is within 180 seconds of now.
func (s *Store) ListServersWithStatus(ctx context.Context, now time.Time) ([]ServerStatus, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT s.id::text, s.name, s.note, s.created_at,
		        a.last_seen_at, COALESCE(a.agent_version, ''), a.cert_not_after
		   FROM servers s
		   LEFT JOIN agents a ON a.server_id = s.id
		  WHERE s.decommissioned_at IS NULL
		  ORDER BY s.name`)
	if err != nil {
		return nil, fmt.Errorf("store: list servers: %w", err)
	}
	defer rows.Close()

	var out []ServerStatus
	for rows.Next() {
		var st ServerStatus
		if err := rows.Scan(&st.ID, &st.Name, &st.Note, &st.CreatedAt,
			&st.LastSeenAt, &st.AgentVersion, &st.CertNotAfter); err != nil {
			return nil, fmt.Errorf("store: scan server: %w", err)
		}
		st.Online = st.LastSeenAt != nil && now.Sub(*st.LastSeenAt) <= onlineWindow
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list servers: %w", err)
	}
	return out, nil
}

// CreateEnrolToken issues a single-use enrolment token for serverID valid for
// ttl from now. Only its SHA-256 is stored; the plaintext is returned once.
func (s *Store) CreateEnrolToken(ctx context.Context, serverID string, ttl time.Duration, now time.Time) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: generate token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO enrolment_tokens (token_hash, server_id, expires_at) VALUES ($1, $2, $3)`,
		HashSecret(plaintext), serverID, now.Add(ttl))
	if err != nil {
		return "", fmt.Errorf("store: create enrolment token: %w", err)
	}
	return plaintext, nil
}

// ConsumeEnrolToken marks the token consumed and returns its server ID. The
// single-use guarantee comes from the conditional UPDATE: concurrent callers
// serialise on the row lock and only one sees consumed_at IS NULL.
func (s *Store) ConsumeEnrolToken(ctx context.Context, plaintext string, now time.Time) (string, error) {
	var serverID string
	err := s.pool.QueryRow(ctx,
		`UPDATE enrolment_tokens SET consumed_at = $2
		  WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
		  RETURNING server_id::text`,
		HashSecret(plaintext), now).Scan(&serverID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTokenInvalid
	}
	if err != nil {
		return "", fmt.Errorf("store: consume enrolment token: %w", err)
	}
	return serverID, nil
}
