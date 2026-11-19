package httpapi

import (
	"sync"
	"time"
)

// RateLimiter is an in-memory token bucket per key. State is lost on restart,
// which is acceptable: it only has to stop a runaway or hostile caller.
type RateLimiter struct {
	mu       sync.Mutex
	capacity float64
	perSec   float64
	buckets  map[string]*bucket
	// lastSweep is when idle buckets were last evicted.
	lastSweep time.Time
}

// sweepInterval is both how often idle buckets are evicted and how long a
// bucket must have been idle to qualify.
const sweepInterval = time.Minute

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows perMinute requests per key per minute, with a burst of
// perMinute.
func NewRateLimiter(perMinute int) *RateLimiter {
	return &RateLimiter{
		capacity: float64(perMinute),
		perSec:   float64(perMinute) / 60,
		buckets:  make(map[string]*bucket),
	}
}

// Allow takes a token for key at time now and reports whether one was available.
func (l *RateLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.capacity, b.tokens+elapsed*l.perSec)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Len reports how many keys currently hold a bucket.
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// sweep drops buckets that have been idle for at least sweepInterval and would
// by now be back at full tokens: forgetting them changes no decision, and it
// bounds the map against callers that rotate keys. The caller holds l.mu.
func (l *RateLimiter) sweep(now time.Time) {
	if l.lastSweep.IsZero() {
		l.lastSweep = now
		return
	}
	if now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		idle := now.Sub(b.last)
		if idle >= sweepInterval && b.tokens+idle.Seconds()*l.perSec >= l.capacity {
			delete(l.buckets, k)
		}
	}
}
