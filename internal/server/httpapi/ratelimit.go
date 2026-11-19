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
}

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
