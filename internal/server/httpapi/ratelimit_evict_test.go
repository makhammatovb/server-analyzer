package httpapi_test

import (
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
