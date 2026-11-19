// Package auth implements accounts, password verification and sessions.
//
// Anyone may register, but an account is inactive until an administrator
// activates it, and an inactive account cannot sign in.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/makhammatovb/fleetguard/internal/server/store"
)

var (
	// ErrInvalidCredentials is returned for every login failure: unknown user,
	// wrong password and inactive account are indistinguishable to the caller.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	// ErrUnauthenticated is returned when a session token is missing, unknown,
	// malformed or expired.
	ErrUnauthenticated = errors.New("auth: no valid session")
	// ErrForbidden is returned when the acting user is not an active administrator.
	ErrForbidden = errors.New("auth: forbidden")
	// ErrInvalidInput is returned for a username, password or role that fails validation.
	ErrInvalidInput = errors.New("auth: invalid input")
	// ErrAdminsExist is returned by Bootstrap when an administrator already exists.
	ErrAdminsExist = errors.New("auth: an administrator already exists")
)

// User is an account as the rest of the application sees it.
type User = store.User

const (
	// SessionTTL is how long a session lives.
	SessionTTL = 7 * 24 * time.Hour

	// RoleAdmin manages servers and users.
	RoleAdmin = "admin"
	// RoleUser has read-only fleet access and may acknowledge incidents.
	RoleUser = "user"

	minPasswordLen = 12
	// maxPasswordLen bounds the work an unauthenticated caller can make us do.
	maxPasswordLen = 256
	minUsernameLen = 3
	maxUsernameLen = 64

	tokenBytes = 32

	// argon2id parameters for new hashes. They are stored in every hash, so
	// raising them later does not invalidate existing passwords.
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonLanes     = 4
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// ErrBusy is returned when every password-hashing slot is in use.
var ErrBusy = errors.New("auth: too many concurrent password operations")

// acquire takes a hashing slot without waiting. Each argon2 run holds 64 MiB,
// so unauthenticated callers must not be able to run an unbounded number at
// once, and queueing would only turn memory exhaustion into goroutine
// exhaustion: when every slot is busy the caller is refused with ErrBusy.
func (s *Service) acquire() (release func(), err error) {
	select {
	case s.slots <- struct{}{}:
		return func() { <-s.slots }, nil
	default:
		return nil, ErrBusy
	}
}

// hash hashes a password inside a slot.
func (s *Service) hash(password string) (string, error) {
	release, err := s.acquire()
	if err != nil {
		return "", err
	}
	defer release()
	if s.observe != nil {
		s.observe()
	}
	return hashPassword(password)
}

// verify checks a password inside a slot.
func (s *Service) verify(password, encoded string) (bool, error) {
	release, err := s.acquire()
	if err != nil {
		return false, err
	}
	defer release()
	if s.observe != nil {
		s.observe()
	}
	return verifyPassword(password, encoded), nil
}

// Option configures a Service.
type Option func(*Service)

// WithMaxConcurrentHashes caps simultaneous argon2 operations.
func WithMaxConcurrentHashes(n int) Option {
	if n < 1 {
		panic("auth: WithMaxConcurrentHashes needs at least one slot")
	}
	return func(s *Service) { s.slots = make(chan struct{}, n) }
}

// WithHashObserver registers fn to be called while a hashing slot is held.
//
// It is a seam for tests (and, later, metrics): it lets a test hold a slot
// open deterministically.
func WithHashObserver(fn func()) Option { return func(s *Service) { s.observe = fn } }

// Service is the authentication service.
type Service struct {
	st    *store.Store
	slots chan struct{}
	// observe, if set, runs while a hashing slot is held.
	observe func()
	// dummyHash is verified against when the username is unknown, so that path
	// does the same hashing work as a real one.
	dummyHash string
}

// New returns a Service backed by st.
func New(st *store.Store, opts ...Option) *Service {
	dummy, err := hashPassword("fleetguard dummy password for unknown users")
	if err != nil {
		panic(fmt.Sprintf("auth: cannot hash dummy password: %v", err))
	}
	svc := &Service{st: st, dummyHash: dummy, slots: make(chan struct{}, 4)}
	for _, o := range opts {
		o(svc)
	}
	return svc
}

func normalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func validate(username, password string) error {
	if n := utf8.RuneCountInString(username); n < minUsernameLen || n > maxUsernameLen {
		return ErrInvalidInput
	}
	if n := len(password); n < minPasswordLen || n > maxPasswordLen {
		return ErrInvalidInput
	}
	return nil
}

// Register creates an inactive account. It returns nil whether or not the
// username was already taken, and spends the same hashing time either way, so
// neither the result nor its timing reveals which usernames exist. The first
// registration for a name wins; a later one never alters the existing account.
func (s *Service) Register(ctx context.Context, username, password string) error {
	username = normalizeUsername(username)
	if err := validate(username, password); err != nil {
		return err
	}
	hash, err := s.hash(password)
	if err != nil {
		return err
	}
	_, err = s.st.CreateUser(ctx, username, hash, RoleUser, false)
	if errors.Is(err, store.ErrUsernameTaken) {
		return nil
	}
	return err
}

// Activate makes userID an active account with role. adminID must be an active
// administrator. The activation is audited with both IDs.
func (s *Service) Activate(ctx context.Context, adminID, userID, role string) error {
	if role != RoleAdmin && role != RoleUser {
		return ErrInvalidInput
	}
	admin, err := s.st.GetUser(ctx, adminID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (admin.Role != RoleAdmin || !admin.IsActive)) {
		return ErrForbidden
	}
	if err != nil {
		return err
	}
	// The store writes the audit row in the same transaction.
	return s.st.ActivateUser(ctx, userID, adminID, role, time.Now().UTC())
}

// Login verifies the credentials and starts a session, returning the session
// token. Every failure is ErrInvalidCredentials, and the password is hashed
// and compared on every path, including an unknown username.
func (s *Service) Login(ctx context.Context, username, password string, now time.Time) (string, error) {
	// Same bound as Register, so argon2 is never handed an arbitrarily long
	// input. Indistinguishable from any other failure.
	if len(password) > maxPasswordLen {
		return "", ErrInvalidCredentials
	}
	user, hash, err := s.st.GetLoginRecord(ctx, normalizeUsername(username))
	known := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if !known {
		hash = s.dummyHash
	}
	ok, err := s.verify(password, hash)
	if err != nil {
		return "", err
	}
	if !known || !ok || !user.IsActive {
		return "", ErrInvalidCredentials
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generate session token: %w", err)
	}
	if err := s.st.CreateSession(ctx, hashToken(raw), user.ID, now, now.Add(SessionTTL)); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Session resolves a session token to its user, or ErrUnauthenticated.
func (s *Service) Session(ctx context.Context, token string, now time.Time) (User, error) {
	h, ok := tokenHashFromString(token)
	if !ok {
		return User{}, ErrUnauthenticated
	}
	u, err := s.st.GetSessionUser(ctx, h, now)
	if errors.Is(err, store.ErrNotFound) {
		return User{}, ErrUnauthenticated
	}
	return u, err
}

// Logout ends the session. An unknown or malformed token is not an error.
func (s *Service) Logout(ctx context.Context, token string) error {
	h, ok := tokenHashFromString(token)
	if !ok {
		return nil
	}
	return s.st.DeleteSession(ctx, h)
}

// CountAdmins returns the number of administrators.
func (s *Service) CountAdmins(ctx context.Context) (int, error) {
	return s.st.CountAdmins(ctx)
}

// Bootstrap creates the first administrator, already active. It returns
// ErrAdminsExist if any administrator exists.
func (s *Service) Bootstrap(ctx context.Context, username, password string) error {
	username = normalizeUsername(username)
	if err := validate(username, password); err != nil {
		return err
	}
	hash, err := s.hash(password)
	if err != nil {
		return err
	}
	_, err = s.st.CreateFirstAdmin(ctx, username, hash)
	if errors.Is(err, store.ErrAdminsExist) {
		return ErrAdminsExist
	}
	return err
}

// hashToken is the stored form of a session token: SHA-256 of 32 random bytes,
// which is safe unsalted because the input is high-entropy.
func hashToken(raw []byte) []byte { return store.HashHighEntropySecret(raw) }

func tokenHashFromString(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenBytes {
		return nil, false
	}
	return hashToken(raw), true
}

// hashPassword returns a PHC-format argon2id hash with a fresh random salt:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonLanes, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		argonMemoryKiB, argonTime, argonLanes,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword checks password against a stored hash using the parameters
// recorded in the hash. A malformed hash never verifies.
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	var memory, iterations uint32
	var lanes uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &lanes); err != nil {
		return false
	}
	// Refuse parameters we would never have written: a corrupted row must not
	// become a memory-exhaustion lever.
	if memory == 0 || memory > 1<<20 || iterations == 0 || iterations > 16 || lanes == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, lanes, uint32(len(want))) //nolint:gosec // len bounded by stored hash
	return subtle.ConstantTimeCompare(got, want) == 1
}
