package store

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	testOnce sync.Once
	testDSN  string
	testErr  error

	testContainer *postgres.PostgresContainer
)

// NewTestDB returns a migrated Store backed by a TimescaleDB container. One
// container is started per test package (the first call) and shared by every
// test in it. It is not terminated per test, because the next test still needs
// it: every package that calls NewTestDB must define a TestMain that calls
// TerminateTestDB after m.Run(). Each call opens its own pool and registers
// t.Cleanup to close it.
//
// Tests sharing the container must not assume an empty database beyond the
// schema; use unique names for the rows they insert.
func NewTestDB(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()

	testOnce.Do(func() {
		c, err := postgres.Run(ctx, TimescaleImage,
			postgres.WithDatabase("fleetguard"),
			postgres.WithUsername("fleetguard"),
			postgres.WithPassword("fleetguard"),
			postgres.BasicWaitStrategies(),
		)
		if err != nil {
			testErr = err
			return
		}
		testContainer = c
		testDSN, testErr = c.ConnectionString(ctx, "sslmode=disable")
	})
	if testErr != nil {
		t.Fatalf("start test database: %v", testErr)
	}

	s, err := Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return s
}

// NewIsolatedTestDB is NewTestDB for a test that needs a database no other test
// has written to (for example one asserting "no administrator exists yet"). It
// creates a fresh, migrated database on the shared container and drops it on
// cleanup.
func NewIsolatedTestDB(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	shared := NewTestDB(t)

	name := "iso_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := shared.pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create isolated database: %v", err)
	}
	u, err := url.Parse(testDSN)
	if err != nil {
		t.Fatalf("parse test dsn: %v", err)
	}
	u.Path = "/" + name
	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		if _, err := shared.pool.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name)); err != nil {
			t.Logf("drop isolated database: %v", err)
		}
	})
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate isolated database: %v", err)
	}
	return s
}

// TerminateTestDB terminates the shared test container, if one was started.
// Call it from TestMain after m.Run() and before os.Exit.
func TerminateTestDB() error {
	if testContainer == nil {
		return nil
	}
	err := testcontainers.TerminateContainer(testContainer)
	testContainer = nil
	return err
}
