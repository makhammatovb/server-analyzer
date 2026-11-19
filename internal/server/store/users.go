package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrUsernameTaken is returned when a username is already in use.
	ErrUsernameTaken = errors.New("store: username already taken")
	// ErrAdminsExist is returned by CreateFirstAdmin when an administrator
	// already exists.
	ErrAdminsExist = errors.New("store: an administrator already exists")
)

// bootstrapLockKey serialises CreateFirstAdmin callers (a transaction-scoped
// Postgres advisory lock), so two processes starting together cannot both see
// zero administrators.
const bootstrapLockKey = 0x46475f41444d // "FG_ADM"

// User is an account. It deliberately carries no password hash: that is
// returned only by GetLoginRecord so it cannot leak through a handler that
// serialises a User.
type User struct {
	ID          string
	Username    string
	Role        string
	IsActive    bool
	CreatedAt   time.Time
	ActivatedAt *time.Time
	ActivatedBy *string
}

const userColumns = `id::text, username, role, is_active, created_at, activated_at, activated_by::text`

func scanUser(row pgx.Row, u *User) error {
	return row.Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.CreatedAt, &u.ActivatedAt, &u.ActivatedBy)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateUser inserts a user. It returns ErrUsernameTaken if the username exists.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string, active bool) (User, error) {
	return createUser(ctx, s.pool, username, passwordHash, role, active)
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func createUser(ctx context.Context, db execer, username, passwordHash, role string, active bool) (User, error) {
	now := time.Now().UTC()
	u := User{ID: uuid.NewString(), Username: username, Role: role, IsActive: active, CreatedAt: now}
	if active {
		u.ActivatedAt = &now
	}
	_, err := db.Exec(ctx,
		`INSERT INTO users (id, username, password_hash, role, is_active, created_at, activated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, username, passwordHash, role, active, now, u.ActivatedAt)
	if isUniqueViolation(err) {
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	return u, nil
}

// CreateFirstAdmin creates an active administrator, but only if none exists.
// It returns ErrAdminsExist otherwise. The check and the insert are one
// transaction under an advisory lock, so concurrent callers cannot both win.
func (s *Store) CreateFirstAdmin(ctx context.Context, username, passwordHash string) (User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(bootstrapLockKey)); err != nil {
		return User{}, fmt.Errorf("store: lock bootstrap: %w", err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin'`).Scan(&n); err != nil {
		return User{}, fmt.Errorf("store: count admins: %w", err)
	}
	if n > 0 {
		return User{}, ErrAdminsExist
	}
	u, err := createUser(ctx, tx, username, passwordHash, "admin", true)
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("store: commit: %w", err)
	}
	return u, nil
}

// CountAdmins returns the number of users with the admin role.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count admins: %w", err)
	}
	return n, nil
}

// GetLoginRecord returns the user and its stored password hash, or ErrNotFound.
func (s *Store) GetLoginRecord(ctx context.Context, username string) (User, string, error) {
	var u User
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+`, password_hash FROM users WHERE username = $1`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.CreatedAt, &u.ActivatedAt, &u.ActivatedBy, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, "", ErrNotFound
	}
	if err != nil {
		return User{}, "", fmt.Errorf("store: get login record: %w", err)
	}
	return u, hash, nil
}

// GetUser returns the user with the given ID, or ErrNotFound.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	if _, err := uuid.Parse(id); err != nil {
		return User{}, ErrNotFound
	}
	var u User
	err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id), &u)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: get user: %w", err)
	}
	return u, nil
}

// ListUsers returns every user, newest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at DESC, username`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := scanUser(rows, &u); err != nil {
			return nil, fmt.Errorf("store: scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ActivateUser activates an inactive user with the given role, recording who
// did it and when, and writes the "user.activated" audit row (both user IDs) in
// the same transaction: either the account is active and audited, or neither
// happened. It returns ErrNotFound if the user does not exist or is already
// active, so a repeat call cannot silently change a role.
func (s *Store) ActivateUser(ctx context.Context, userID, adminID, role string, now time.Time) error {
	if _, err := uuid.Parse(userID); err != nil {
		return ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE users SET is_active = true, role = $2, activated_at = $3, activated_by = $4
		 WHERE id = $1 AND NOT is_active`, userID, role, now, adminID)
	if err != nil {
		return fmt.Errorf("store: activate user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := appendAudit(ctx, tx, adminID, "user.activated", userID,
		map[string]string{"admin_id": adminID, "user_id": userID, "role": role}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit activation: %w", err)
	}
	return nil
}

// CreateSession stores a session by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID string, now, expires time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		tokenHash, userID, now, expires)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSessionUser returns the user owning an unexpired session, or ErrNotFound
// for an unknown or expired session or one whose user is not active. Expiry is
// checked here, against now, rather than left to a cleanup sweep.
func (s *Store) GetSessionUser(ctx context.Context, tokenHash []byte, now time.Time) (User, error) {
	var u User
	err := scanUser(s.pool.QueryRow(ctx,
		`SELECT u.id::text, u.username, u.role, u.is_active, u.created_at, u.activated_at, u.activated_by::text
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1 AND s.expires_at > $2 AND u.is_active`, tokenHash, now), &u)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: get session: %w", err)
	}
	return u, nil
}

// DeleteSession removes a session. Deleting an unknown session is not an error.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}
