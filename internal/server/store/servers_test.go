package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/store"
)

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.NewString())
}

func TestCreateServerRejectsDuplicateName(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	name := uniqueName("dup")

	created, err := s.CreateServer(ctx, name, "first")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	got, err := s.GetServer(ctx, created.ID)
	if err != nil || got.Name != name || got.Note != "first" {
		t.Fatalf("GetServer = %+v, %v", got, err)
	}
	if _, err := s.CreateServer(ctx, name, "second"); !errors.Is(err, store.ErrNameTaken) {
		t.Fatalf("duplicate err = %v, want ErrNameTaken", err)
	}
	if _, err := s.GetServer(ctx, uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing err = %v, want ErrNotFound", err)
	}
}

func TestConsumeEnrolTokenSucceedsOnce(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	srv, _ := s.CreateServer(ctx, uniqueName("once"), "")
	tok, err := s.CreateEnrolToken(ctx, srv.ID, time.Hour, now)
	if err != nil {
		t.Fatalf("CreateEnrolToken: %v", err)
	}

	id, err := s.ConsumeEnrolToken(ctx, tok, now)
	if err != nil || id != srv.ID {
		t.Fatalf("first consume = %q, %v; want %q", id, err, srv.ID)
	}
	if _, err := s.ConsumeEnrolToken(ctx, tok, now); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("second consume err = %v, want ErrTokenInvalid", err)
	}
	if _, err := s.ConsumeEnrolToken(ctx, "unknown-token", now); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("unknown token err = %v, want ErrTokenInvalid", err)
	}
}

func TestEnrolTokenIsStoredHashedOnly(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	srv, _ := s.CreateServer(ctx, uniqueName("hashed"), "")
	tok, err := s.CreateEnrolToken(ctx, srv.ID, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM enrolment_tokens WHERE server_id = $1 AND token_hash = $2`,
		srv.ID, []byte(tok)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("plaintext token found in token_hash column")
	}
}

func TestConsumeEnrolTokenRejectsExpired(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	srv, _ := s.CreateServer(ctx, uniqueName("expired"), "")
	tok, err := s.CreateEnrolToken(ctx, srv.ID, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeEnrolToken(ctx, tok, now.Add(2*time.Hour)); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("expired err = %v, want ErrTokenInvalid", err)
	}
}

func TestConsumeEnrolTokenIsAtomicUnderConcurrency(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	srv, _ := s.CreateServer(ctx, uniqueName("race"), "")
	tok, err := s.CreateEnrolToken(ctx, srv.ID, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 10
	var wg sync.WaitGroup
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = s.ConsumeEnrolToken(ctx, tok, now)
		}()
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case !errors.Is(err, store.ErrTokenInvalid):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d consumers succeeded, want exactly 1", succeeded)
	}
}

func TestListServersWithStatusComputesOnline(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	enrol := func(name string, lastSeen *time.Time) string {
		srv, err := s.CreateServer(ctx, uniqueName(name), "")
		if err != nil {
			t.Fatal(err)
		}
		if lastSeen == nil {
			return srv.ID
		}
		err = s.RecordEnrolment(ctx, store.Enrolment{
			ServerID: srv.ID, Hostname: "h", AgentVersion: "1.2.3",
			CertFingerprint: "fp", EnrolKeyHash: []byte("k"), CertNotAfter: now.Add(24 * time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.TouchHeartbeat(ctx, srv.ID, "1.2.3", "boot", *lastSeen); err != nil {
			t.Fatal(err)
		}
		return srv.ID
	}
	recent, stale := now.Add(-60*time.Second), now.Add(-600*time.Second)
	recentID := enrol("recent", &recent)
	staleID := enrol("stale", &stale)
	neverID := enrol("never", nil)

	list, err := s.ListServersWithStatus(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]store.ServerStatus{}
	for _, st := range list {
		byID[st.ID] = st
	}
	for id, want := range map[string]bool{recentID: true, staleID: false, neverID: false} {
		got, ok := byID[id]
		if !ok {
			t.Fatalf("server %s missing from list", id)
		}
		if got.Online != want {
			t.Errorf("server %s Online = %v, want %v", id, got.Online, want)
		}
	}
	if r := byID[recentID]; r.AgentVersion != "1.2.3" || r.LastSeenAt == nil || r.CertNotAfter == nil {
		t.Errorf("recent status = %+v", r)
	}
	if n := byID[neverID]; n.LastSeenAt != nil || n.CertNotAfter != nil || n.AgentVersion != "" {
		t.Errorf("never status = %+v", n)
	}
}
