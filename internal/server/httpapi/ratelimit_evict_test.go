package httpapi_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
)

func TestRateLimiterEvictsIdleFullBuckets(t *testing.T) {
	l := httpapi.NewRateLimiter(10)
	t0 := time.Now()
	for i := range 100 {
		l.Allow(string(rune('a'+i%26))+string(rune('A'+i/26)), t0)
	}
	if l.Len() != 100 {
		t.Fatalf("Len = %d, want 100", l.Len())
	}
	// Two minutes on, every earlier bucket has refilled and sat idle: the next
	// call sweeps them, leaving only the new key.
	l.Allow("fresh", t0.Add(2*time.Minute))
	if l.Len() != 1 {
		t.Fatalf("Len = %d after the idle window, want 1", l.Len())
	}
}

func TestRateLimiterRefusesNewKeysPastItsCeiling(t *testing.T) {
	l := httpapi.NewRateLimiterWithMax(10, 5)
	t0 := time.Now()
	for i := range 5 {
		if !l.Allow(fmt.Sprintf("k%d", i), t0) {
			t.Fatalf("key %d refused below the ceiling", i)
		}
	}
	if l.Allow("one-too-many", t0) {
		t.Fatal("a new key was admitted past the ceiling")
	}
	if l.Len() != 5 {
		t.Fatalf("Len = %d, want 5: the map grew past its ceiling", l.Len())
	}
	if !l.Allow("k0", t0) {
		t.Fatal("an already-tracked key must keep working at the ceiling")
	}
	// Once the idle buckets are swept there is room again.
	if !l.Allow("later", t0.Add(2*time.Minute)) {
		t.Fatal("a new key was refused after idle buckets could be evicted")
	}
}
