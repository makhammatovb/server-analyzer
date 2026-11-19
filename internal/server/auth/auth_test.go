package auth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/auth"
	"github.com/makhammatovb/fleetguard/internal/server/store"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if err := store.TerminateTestDB(); err != nil {
		fmt.Fprintf(os.Stderr, "terminate test database: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

const goodPassword = "correct horse battery staple" //nolint:gosec // test fixture

func uname() string { return "u-" + uuid.NewString() }

func newSvc(t *testing.T) (*auth.Service, *store.Store) {
	t.Helper()
	st := store.NewTestDB(t)
	return auth.New(st), st
}

// admin creates an active administrator directly in the store.
func admin(t *testing.T, st *store.Store) store.User {
	t.Helper()
	u, err := st.CreateUser(context.Background(), uname(), "x", "admin", true)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	return u
}

func sessionCount(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	now := time.Now()

	inactive := uname()
	if err := svc.Register(ctx, inactive, goodPassword); err != nil {
		t.Fatal(err)
	}
	active := uname()
	if err := svc.Register(ctx, active, goodPassword); err != nil {
		t.Fatal(err)
	}
	u, _, _ := st.GetLoginRecord(ctx, active)
	if err := svc.Activate(ctx, admin(t, st).ID, u.ID, "user"); err != nil {
		t.Fatal(err)
	}

	before := sessionCount(t, st)
	cases := map[string][2]string{
		"unknown user":   {uname(), goodPassword},
		"wrong password": {active, "not the right password"},
		"inactive user":  {inactive, goodPassword},
	}
	for name, c := range cases {
		tok, err := svc.Login(ctx, c[0], c[1], now)
		if !errors.Is(err, auth.ErrInvalidCredentials) || tok != "" {
			t.Errorf("%s: got token %q err %v, want ErrInvalidCredentials", name, tok, err)
		}
	}
	if after := sessionCount(t, st); after != before {
		t.Fatalf("failed logins created %d sessions", after-before)
	}
}

// An unknown username must cost the same hashing work as a wrong password, or
// response time discloses which accounts exist.
func TestLoginUnknownUserCostsAsMuchAsWrongPassword(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	if err := svc.Register(ctx, name, goodPassword); err != nil {
		t.Fatal(err)
	}
	u, _, _ := st.GetLoginRecord(ctx, name)
	if err := svc.Activate(ctx, admin(t, st).ID, u.ID, "user"); err != nil {
		t.Fatal(err)
	}
	fastest := func(username string) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			_, _ = svc.Login(ctx, username, "wrong password here", time.Now())
			best = min(best, time.Since(start))
		}
		return best
	}
	known, unknown := fastest(name), fastest(uname())
	if unknown*3 < known {
		t.Fatalf("unknown-user login took %v, wrong-password login %v: timing leaks account existence", unknown, known)
	}
}

func TestInactiveUserGetsNoSession(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	if err := svc.Register(ctx, name, goodPassword); err != nil {
		t.Fatal(err)
	}
	u, _, _ := st.GetLoginRecord(ctx, name)
	if u.IsActive {
		t.Fatal("registered user is active")
	}
	if _, err := svc.Login(ctx, name, goodPassword, time.Now()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
	var n int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("inactive user has %d sessions", n)
	}
}

func TestActivatedUserCanLogin(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	u, _, _ := st.GetLoginRecord(ctx, name)
	if err := svc.Activate(ctx, admin(t, st).ID, u.ID, "user"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := svc.Login(ctx, name, goodPassword, now)
	if err != nil || tok == "" {
		t.Fatalf("Login = %q, %v", tok, err)
	}
	got, err := svc.Session(ctx, tok, now.Add(time.Minute))
	if err != nil || got.ID != u.ID || got.Role != "user" {
		t.Fatalf("Session = %+v, %v", got, err)
	}
	// The raw token must not be stored.
	var n int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE encode(token_hash,'escape') = $1`, tok).Scan(&n)
	if n != 0 {
		t.Fatal("session token stored in plaintext")
	}
}

func TestPasswordIsStoredAsArgon2id(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	_, hash, err := st.GetLoginRecord(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") || strings.Contains(hash, goodPassword) {
		t.Fatalf("stored hash %q is not argon2id with the required parameters", hash)
	}
}

func TestRegisterDoesNotRevealTakenUsername(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	if err := svc.Register(ctx, name, goodPassword); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := svc.Register(ctx, name, "a different password entirely"); err != nil {
		t.Fatalf("second Register must look identical, got %v", err)
	}
	var n int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM users WHERE username = $1`, name).Scan(&n)
	if n != 1 {
		t.Fatalf("%d rows for the username, want 1", n)
	}
	// The second registration must not have replaced the first password.
	u, _, _ := st.GetLoginRecord(ctx, name)
	_ = svc.Activate(ctx, admin(t, st).ID, u.ID, "user")
	if _, err := svc.Login(ctx, name, goodPassword, time.Now()); err != nil {
		t.Fatalf("original password no longer works: %v", err)
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	svc, _ := newSvc(t)
	for name, c := range map[string][2]string{
		"empty username": {"", goodPassword},
		"short password": {uname(), "short"},
		"huge password":  {uname(), strings.Repeat("a", 1000)},
		"huge username":  {strings.Repeat("a", 200), goodPassword},
	} {
		if err := svc.Register(context.Background(), c[0], c[1]); !errors.Is(err, auth.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
}

func TestActivateRequiresAdmin(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	plain, err := st.CreateUser(ctx, uname(), "x", "user", true)
	if err != nil {
		t.Fatal(err)
	}
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	target, _, _ := st.GetLoginRecord(ctx, name)
	if err := svc.Activate(ctx, plain.ID, target.ID, "user"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	got, _ := st.GetUser(ctx, target.ID)
	if got.IsActive {
		t.Fatal("target was activated by a non-admin")
	}
	// An inactive admin does not count either.
	dormant, _ := st.CreateUser(ctx, uname(), "x", "admin", false)
	if err := svc.Activate(ctx, dormant.ID, target.ID, "user"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("inactive admin err = %v, want ErrForbidden", err)
	}
}

func TestActivateRejectsUnknownRole(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	target, _, _ := st.GetLoginRecord(ctx, name)
	if err := svc.Activate(ctx, admin(t, st).ID, target.ID, "superuser"); !errors.Is(err, auth.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestActivateIsAudited(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	adm := admin(t, st)
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	target, _, _ := st.GetLoginRecord(ctx, name)
	if err := svc.Activate(ctx, adm.ID, target.ID, "user"); err != nil {
		t.Fatal(err)
	}
	var actor, tgt, detail string
	err := st.Pool().QueryRow(ctx,
		`SELECT actor, target, detail::text FROM audit_log WHERE action = 'user.activated' AND target = $1`,
		target.ID).Scan(&actor, &tgt, &detail)
	if err != nil {
		t.Fatalf("no audit row: %v", err)
	}
	if actor != adm.ID || tgt != target.ID || !strings.Contains(detail, adm.ID) || !strings.Contains(detail, target.ID) {
		t.Fatalf("audit row actor=%q target=%q detail=%s lacks both ids", actor, tgt, detail)
	}
}

func TestSessionExpires(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	u, _, _ := st.GetLoginRecord(ctx, name)
	_ = svc.Activate(ctx, admin(t, st).ID, u.ID, "user")
	now := time.Now()
	tok, err := svc.Login(ctx, name, goodPassword, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Session(ctx, tok, now.Add(6*24*time.Hour)); err != nil {
		t.Fatalf("session should still be valid at 6 days: %v", err)
	}
	if _, err := svc.Session(ctx, tok, now.Add(8*24*time.Hour)); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("err at 8 days = %v, want ErrUnauthenticated", err)
	}
}

func TestSessionRejectsGarbageToken(t *testing.T) {
	svc, _ := newSvc(t)
	for _, tok := range []string{"", "!!!", "AAAA"} {
		if _, err := svc.Session(context.Background(), tok, time.Now()); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("token %q: err = %v", tok, err)
		}
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	name := uname()
	_ = svc.Register(ctx, name, goodPassword)
	u, _, _ := st.GetLoginRecord(ctx, name)
	_ = svc.Activate(ctx, admin(t, st).ID, u.ID, "user")
	now := time.Now()
	tok, _ := svc.Login(ctx, name, goodPassword, now)
	if err := svc.Logout(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Session(ctx, tok, now); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestBootstrapOnlyWhenNoAdminsExist(t *testing.T) {
	st := store.NewIsolatedTestDB(t)
	svc := auth.New(st)
	ctx := context.Background()
	if n, err := svc.CountAdmins(ctx); err != nil || n != 0 {
		t.Fatalf("CountAdmins = %d, %v", n, err)
	}
	name := uname()
	if err := svc.Bootstrap(ctx, name, goodPassword); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	if err := svc.Bootstrap(ctx, uname(), goodPassword); !errors.Is(err, auth.ErrAdminsExist) {
		t.Fatalf("second Bootstrap err = %v, want ErrAdminsExist", err)
	}
	// The bootstrap admin is active and can sign in straight away.
	tok, err := svc.Login(ctx, name, goodPassword, time.Now())
	if err != nil {
		t.Fatalf("bootstrap admin cannot log in: %v", err)
	}
	if u, err := svc.Session(ctx, tok, time.Now()); err != nil || u.Role != "admin" {
		t.Fatalf("Session = %+v, %v", u, err)
	}
}
