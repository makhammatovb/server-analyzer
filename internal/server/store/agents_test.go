package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/store"
)

func enrolAgent(t *testing.T, s *store.Store, secret string) string {
	t.Helper()
	ctx := context.Background()
	srv, err := s.CreateServer(ctx, uniqueName("agent"), "")
	if err != nil {
		t.Fatal(err)
	}
	err = s.RecordEnrolment(ctx, store.Enrolment{
		ServerID: srv.ID, Hostname: "host", AgentVersion: "0.1.0",
		CertFingerprint: "fp", EnrolKeyHash: store.HashHighEntropySecret([]byte(secret)),
		CertNotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("RecordEnrolment: %v", err)
	}
	return srv.ID
}

func TestVerifyEnrolKeyRejectsWrongKey(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	id := enrolAgent(t, s, "right-secret")

	if err := s.VerifyEnrolKey(ctx, id, "right-secret"); err != nil {
		t.Fatalf("correct key: %v", err)
	}
	if err := s.VerifyEnrolKey(ctx, id, "wrong-secret"); !errors.Is(err, store.ErrEnrolKeyInvalid) {
		t.Fatalf("wrong key err = %v, want ErrEnrolKeyInvalid", err)
	}
	if err := s.VerifyEnrolKey(ctx, uuid.NewString(), "right-secret"); !errors.Is(err, store.ErrEnrolKeyInvalid) {
		t.Fatalf("unknown server err = %v, want ErrEnrolKeyInvalid", err)
	}
}

func TestRecordEnrolmentUpsertsOnServerID(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	id := enrolAgent(t, s, "first")
	err := s.RecordEnrolment(ctx, store.Enrolment{
		ServerID: id, Hostname: "host2", AgentVersion: "0.2.0",
		CertFingerprint: "fp2", EnrolKeyHash: store.HashHighEntropySecret([]byte("second")),
		CertNotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	if err := s.VerifyEnrolKey(ctx, id, "second"); err != nil {
		t.Fatalf("new key rejected: %v", err)
	}
	if err := s.VerifyEnrolKey(ctx, id, "first"); !errors.Is(err, store.ErrEnrolKeyInvalid) {
		t.Fatalf("old key err = %v, want ErrEnrolKeyInvalid", err)
	}
}

func TestTouchHeartbeatReportsBootIDChange(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	id := enrolAgent(t, s, "k")
	at := time.Now().UTC().Truncate(time.Microsecond)

	// First heartbeat: stored boot ID is empty, so not a change.
	if changed, err := s.TouchHeartbeat(ctx, id, "0.1.0", "boot-a", at); err != nil || changed {
		t.Fatalf("first = %v, %v; want false, nil", changed, err)
	}
	if changed, err := s.TouchHeartbeat(ctx, id, "0.1.0", "boot-a", at.Add(time.Minute)); err != nil || changed {
		t.Fatalf("same boot = %v, %v; want false, nil", changed, err)
	}
	// Empty incoming boot ID is not a change and must not erase the stored one.
	if changed, err := s.TouchHeartbeat(ctx, id, "0.1.0", "", at.Add(2*time.Minute)); err != nil || changed {
		t.Fatalf("empty boot = %v, %v; want false, nil", changed, err)
	}
	// Changed boot ID is a signal, not a rejection: last_seen_at still updates.
	later := at.Add(3 * time.Minute)
	if changed, err := s.TouchHeartbeat(ctx, id, "0.2.0", "boot-b", later); err != nil || !changed {
		t.Fatalf("new boot = %v, %v; want true, nil", changed, err)
	}
	var lastSeen time.Time
	var ver, boot string
	if err := s.Pool().QueryRow(ctx,
		`SELECT last_seen_at, agent_version, boot_id FROM agents WHERE server_id = $1`, id).
		Scan(&lastSeen, &ver, &boot); err != nil {
		t.Fatal(err)
	}
	if !lastSeen.Equal(later) || ver != "0.2.0" || boot != "boot-b" {
		t.Fatalf("stored = %v %q %q", lastSeen, ver, boot)
	}
	if _, err := s.TouchHeartbeat(ctx, uuid.NewString(), "v", "b", at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown agent err = %v, want ErrNotFound", err)
	}
}

func TestAppendAuditStoresDetailAsJSON(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	target := "server:" + uuid.NewString()

	detail := map[string]any{"hostname": "web-1", "attempts": 2}
	if err := s.AppendAudit(ctx, "agent", "enrol", target, detail); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := s.AppendAudit(ctx, "agent", "enrol-nil", target, nil); err != nil {
		t.Fatalf("AppendAudit nil detail: %v", err)
	}

	var actor, action string
	var raw []byte
	if err := s.Pool().QueryRow(ctx,
		`SELECT actor, action, detail FROM audit_log WHERE target = $1 AND action = 'enrol'`, target).
		Scan(&actor, &action, &raw); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("detail not JSON: %v", err)
	}
	if actor != "agent" || got["hostname"] != "web-1" || got["attempts"] != float64(2) {
		t.Fatalf("stored actor=%q detail=%v", actor, got)
	}
	var nilDetail string
	if err := s.Pool().QueryRow(ctx,
		`SELECT detail::text FROM audit_log WHERE target = $1 AND action = 'enrol-nil'`, target).
		Scan(&nilDetail); err != nil || nilDetail != "{}" {
		t.Fatalf("nil detail = %q, %v; want {}", nilDetail, err)
	}
}

func revoke(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if _, err := s.Pool().Exec(context.Background(),
		`UPDATE agents SET revoked_at = now() WHERE server_id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func decommission(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if _, err := s.Pool().Exec(context.Background(),
		`UPDATE servers SET decommissioned_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedAgentIsRefused(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	id := enrolAgent(t, s, "k")
	revoke(t, s, id)

	if err := s.VerifyEnrolKey(ctx, id, "k"); !errors.Is(err, store.ErrEnrolKeyInvalid) {
		t.Fatalf("verify err = %v, want ErrEnrolKeyInvalid", err)
	}
	if _, err := s.TouchHeartbeat(ctx, id, "v", "b", time.Now()); !errors.Is(err, store.ErrServerInactive) {
		t.Fatalf("heartbeat err = %v, want ErrServerInactive", err)
	}
}

func TestDecommissionedServerIsRefused(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := enrolAgent(t, s, "k")
	tok, err := s.CreateEnrolToken(ctx, id, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	decommission(t, s, id)

	if err := s.VerifyEnrolKey(ctx, id, "k"); !errors.Is(err, store.ErrEnrolKeyInvalid) {
		t.Fatalf("verify err = %v, want ErrEnrolKeyInvalid", err)
	}
	if _, err := s.TouchHeartbeat(ctx, id, "v", "b", now); !errors.Is(err, store.ErrServerInactive) {
		t.Fatalf("heartbeat err = %v, want ErrServerInactive", err)
	}
	if _, err := s.ConsumeEnrolToken(ctx, tok, now); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("consume err = %v, want ErrTokenInvalid", err)
	}
}

func TestRecordEnrolmentClearsRevocation(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	id := enrolAgent(t, s, "old")
	revoke(t, s, id)
	err := s.RecordEnrolment(ctx, store.Enrolment{
		ServerID: id, Hostname: "h", AgentVersion: "1", CertFingerprint: "fp",
		EnrolKeyHash: store.HashHighEntropySecret([]byte("new")), CertNotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyEnrolKey(ctx, id, "new"); err != nil {
		t.Fatalf("verify after re-enrol: %v", err)
	}
	if _, err := s.TouchHeartbeat(ctx, id, "1", "b", time.Now()); err != nil {
		t.Fatalf("heartbeat after re-enrol: %v", err)
	}
}

func TestTouchHeartbeatKeepsVersionWhenEmpty(t *testing.T) {
	s := store.NewTestDB(t)
	ctx := context.Background()
	id := enrolAgent(t, s, "k")
	if _, err := s.TouchHeartbeat(ctx, id, "", "b", time.Now()); err != nil {
		t.Fatal(err)
	}
	var ver string
	if err := s.Pool().QueryRow(ctx, `SELECT agent_version FROM agents WHERE server_id = $1`, id).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != "0.1.0" {
		t.Fatalf("agent_version = %q, want 0.1.0", ver)
	}
}
