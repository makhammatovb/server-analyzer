package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/makhammatovb/fleetguard/internal/server/store"
)

// TestMain terminates the shared container once, after every test has run.
// Termination happens before os.Exit (which skips defers) and the exit code
// from m.Run() is preserved even when tests fail.
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

func TestMigrateCreatesEveryTable(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()

	tables := []string{
		"users", "sessions", "servers", "enrolment_tokens",
		"agents", "audit_log", "user_server_scopes",
	}
	for _, name := range tables {
		var exists bool
		err := s.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'public' AND table_name = $1)`, name).Scan(&exists)
		if err != nil {
			t.Fatalf("query for table %s: %v", name, err)
		}
		if !exists {
			t.Errorf("table %s was not created by the migrations", name)
		}
	}
}

func TestAuditLogIsHypertable(t *testing.T) {
	s := store.NewTestDB(t)

	var n int
	err := s.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM timescaledb_information.hypertables
		 WHERE hypertable_name = 'audit_log'`).Scan(&n)
	if err != nil {
		t.Fatalf("query hypertables: %v", err)
	}
	if n != 1 {
		t.Fatalf("audit_log hypertable rows = %d, want 1", n)
	}
}

func TestRoleCheckRejectsUnknownRole(t *testing.T) {
	s := store.NewTestDB(t)

	_, err := s.Pool().Exec(context.Background(),
		`INSERT INTO users (id, username, password_hash, role, created_at)
		 VALUES (gen_random_uuid(), 'mallory', 'x', 'root', now())`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("err = %v, want a *pgconn.PgError", err)
	}
	if pgErr.Code != "23514" { // check_violation
		t.Fatalf("SQLSTATE = %s, want 23514 (check_violation)", pgErr.Code)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()

	// NewTestDB has already migrated once; two more runs must be no-ops.
	for i := 0; i < 2; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate run %d: %v", i+1, err)
		}
	}
}
