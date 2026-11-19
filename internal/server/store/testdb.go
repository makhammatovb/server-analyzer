package store

import (
	"context"
	"sync"
	"testing"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	testOnce sync.Once
	testDSN  string
	testErr  error
)

// NewTestDB returns a migrated Store backed by a TimescaleDB container. One
// container is started per test package (the first call) and shared by every
// test in it. The container is not terminated per test, because the next test
// still needs it; testcontainers' reaper (Ryuk) removes it when the test
// process exits. Each call opens its own pool and registers t.Cleanup to
// close it.
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
