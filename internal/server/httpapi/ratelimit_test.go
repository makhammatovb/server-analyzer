package httpapi_test

import (
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
)

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := httpapi.NewRateLimiter(60)
	now := time.Now()
	for i := 0; i < 60; i++ {
		if !rl.Allow("a", now) {
			t.Fatalf("request %d denied within the burst", i+1)
		}
	}
	if rl.Allow("a", now) {
		t.Fatal("61st request allowed")
	}
	if !rl.Allow("a", now.Add(time.Second)) {
		t.Fatal("no token refilled after one second at 60/min")
	}
	if rl.Allow("a", now.Add(time.Second)) {
		t.Fatal("refill granted more than one token per second")
	}
	if !rl.Allow("b", now) {
		t.Fatal("another key was affected")
	}
}
