package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/store"
)

func uname() string { return "u-" + uuid.NewString() }

func TestCreateUserAndLookup(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	name := uname()
	u, err := s.CreateUser(ctx, name, "hash-1", "user", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.IsActive || u.Role != "user" || u.Username != name {
		t.Fatalf("unexpected user %+v", u)
	}
	got, hash, err := s.GetLoginRecord(ctx, name)
	if err != nil || got.ID != u.ID || hash != "hash-1" {
		t.Fatalf("GetLoginRecord = %+v %q %v", got, hash, err)
	}
	if _, _, err := s.GetLoginRecord(ctx, uname()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user err = %v, want ErrNotFound", err)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	name := uname()
	if _, err := s.CreateUser(ctx, name, "h", "user", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, name, "h", "user", false); !errors.Is(err, store.ErrUsernameTaken) {
		t.Fatalf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestActivateUserRecordsWhoAndWhen(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	admin, err := s.CreateUser(ctx, uname(), "h", "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.CreateUser(ctx, uname(), "h", "user", false)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.ActivateUser(ctx, u.ID, admin.ID, "user", now); err != nil {
		t.Fatalf("ActivateUser: %v", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsActive || got.ActivatedBy == nil || *got.ActivatedBy != admin.ID || got.ActivatedAt == nil {
		t.Fatalf("activation not recorded: %+v", got)
	}
	// Activating an already-active or unknown user is ErrNotFound.
	if err := s.ActivateUser(ctx, u.ID, admin.ID, "admin", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("re-activate err = %v, want ErrNotFound", err)
	}
	if err := s.ActivateUser(ctx, uuid.NewString(), admin.ID, "user", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown err = %v, want ErrNotFound", err)
	}
	if err := s.ActivateUser(ctx, "not-a-uuid", admin.ID, "user", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad id err = %v, want ErrNotFound", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, uname(), "h", "user", true)
	hash := []byte(uuid.NewString())
	now := time.Now().UTC()
	if err := s.CreateSession(ctx, hash, u.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := s.GetSessionUser(ctx, hash, now.Add(time.Minute))
	if err != nil || got.ID != u.ID {
		t.Fatalf("GetSessionUser = %+v %v", got, err)
	}
	if _, err := s.GetSessionUser(ctx, hash, now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteSession(ctx, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSessionUser(ctx, hash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted session err = %v, want ErrNotFound", err)
	}
}

func TestSessionOfInactiveUserIsRejected(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, uname(), "h", "user", false)
	hash := []byte(uuid.NewString())
	now := time.Now().UTC()
	if err := s.CreateSession(ctx, hash, u.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSessionUser(ctx, hash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListUsersIncludesCreated(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, uname(), "h", "user", false)
	all, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range all {
		if x.ID == u.ID {
			return
		}
	}
	t.Fatal("created user not listed")
}

func TestCreateFirstAdminOnlyOnce(t *testing.T) {
	s := store.NewIsolatedTestDB(t)
	ctx := context.Background()
	if n, err := s.CountAdmins(ctx); err != nil || n != 0 {
		t.Fatalf("CountAdmins = %d, %v; want 0", n, err)
	}
	a, err := s.CreateFirstAdmin(ctx, uname(), "h")
	if err != nil || !a.IsActive || a.Role != "admin" {
		t.Fatalf("CreateFirstAdmin = %+v %v", a, err)
	}
	if n, _ := s.CountAdmins(ctx); n != 1 {
		t.Fatalf("CountAdmins = %d, want 1", n)
	}
	if _, err := s.CreateFirstAdmin(ctx, uname(), "h"); !errors.Is(err, store.ErrAdminsExist) {
		t.Fatalf("second err = %v, want ErrAdminsExist", err)
	}
}

func TestCreateFirstAdminIsRaceSafe(t *testing.T) {
	s := store.NewIsolatedTestDB(t)
	ctx := context.Background()
	const n = 8
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := s.CreateFirstAdmin(ctx, uname(), "h")
			errs <- err
		}()
	}
	created := 0
	for range n {
		if err := <-errs; err == nil {
			created++
		} else if !errors.Is(err, store.ErrAdminsExist) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if created != 1 {
		t.Fatalf("%d concurrent bootstraps succeeded, want exactly 1", created)
	}
}

func TestActivateUserWritesAuditRow(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	admin, _ := s.CreateUser(ctx, uname(), "h", "admin", true)
	u, _ := s.CreateUser(ctx, uname(), "h", "user", false)
	if err := s.ActivateUser(ctx, u.ID, admin.ID, "user", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var actor, detail string
	err := s.Pool().QueryRow(ctx,
		`SELECT actor, detail::text FROM audit_log WHERE action = 'user.activated' AND target = $1`, u.ID).
		Scan(&actor, &detail)
	if err != nil {
		t.Fatalf("no audit row: %v", err)
	}
	if actor != admin.ID || !strings.Contains(detail, admin.ID) || !strings.Contains(detail, u.ID) {
		t.Fatalf("audit actor=%q detail=%s lacks both ids", actor, detail)
	}
}

// If the audit insert fails the activation must not stand, and a retry must
// not be told the user is "not found".
func TestActivateUserIsAtomicWithItsAudit(t *testing.T) {
	s := store.NewIsolatedTestDB(t)
	ctx := context.Background()
	admin, _ := s.CreateUser(ctx, uname(), "h", "admin", true)
	u, _ := s.CreateUser(ctx, uname(), "h", "user", false)
	for _, q := range []string{
		`CREATE FUNCTION refuse_audit() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION refuse_audit()`,
	} {
		if _, err := s.Pool().Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	err := s.ActivateUser(ctx, u.ID, admin.ID, "admin", time.Now().UTC())
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want the audit failure", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.IsActive || got.Role != "user" {
		t.Fatalf("activation stood without its audit row: %+v", got)
	}
	if _, err := s.Pool().Exec(ctx, `DROP TRIGGER refuse_audit ON audit_log`); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateUser(ctx, u.ID, admin.ID, "user", time.Now().UTC()); err != nil {
		t.Fatalf("retry after the audit recovered: %v", err)
	}
}
