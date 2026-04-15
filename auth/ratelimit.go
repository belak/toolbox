package auth

import (
	"math"
	"sync"
	"time"
)

// RateLimiter implements a per-key leaky bucket rate limiter. Keys are
// arbitrary strings (e.g. "login:user@example.com", "login-ip:1.2.3.4").
//
// Not suitable for distributed deployments; use an external store (Redis)
// for that. This is for single-instance apps.
type RateLimiter struct {
	mu            sync.Mutex
	buckets       map[string]*bucket
	lastCleanup   time.Time
	cleanupEvery  time.Duration
	defaultRate   float64
	defaultPeriod time.Duration
}

type bucket struct {
	value float64 // current fill level
	at    time.Time
	rate  float64
	per   time.Duration
}

// drain updates the bucket's fill level based on elapsed time.
func (b *bucket) drain(now time.Time) {
	elapsed := now.Sub(b.at).Seconds()
	perSec := b.per.Seconds()
	if perSec > 0 {
		b.value = math.Max(0, b.value-elapsed*b.rate/perSec)
	}
	b.at = now
}

// RateLimiterOption configures a RateLimiter.
type RateLimiterOption func(*RateLimiter)

// WithCleanupInterval sets how often stale buckets are removed
// (default: 10 minutes).
func WithCleanupInterval(d time.Duration) RateLimiterOption {
	return func(r *RateLimiter) { r.cleanupEvery = d }
}

// NewRateLimiter creates a rate limiter. The rate is the maximum number of
// operations allowed in the given period before throttling kicks in.
//
// Example: NewRateLimiter(5, time.Hour) allows 5 attempts per hour per key.
func NewRateLimiter(rate float64, period time.Duration, opts ...RateLimiterOption) *RateLimiter {
	r := &RateLimiter{
		buckets:       make(map[string]*bucket),
		lastCleanup:   time.Now(),
		cleanupEvery:  10 * time.Minute,
		defaultRate:   rate,
		defaultPeriod: period,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Allow checks whether the operation identified by key is allowed. If
// allowed, it consumes one unit from the bucket and returns true.
func (r *RateLimiter) Allow(key string) bool {
	return r.AllowN(key, 1)
}

// AllowN checks whether n units of the operation are allowed. If allowed,
// it consumes n units and returns true.
func (r *RateLimiter) AllowN(key string, n float64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.cleanup(now)

	b := r.getBucket(key, now)
	if b.value+n > b.rate {
		return false
	}
	b.value += n
	return true
}

// Check reports whether the operation would be allowed without consuming
// any units.
func (r *RateLimiter) Check(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b := r.getBucket(key, now)
	return b.value+1 <= b.rate
}

// Reset removes the bucket for the given key, fully restoring its quota.
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buckets, key)
}

func (r *RateLimiter) getBucket(key string, now time.Time) *bucket {
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{
			at:   now,
			rate: r.defaultRate,
			per:  r.defaultPeriod,
		}
		r.buckets[key] = b
	} else {
		b.drain(now)
	}
	return b
}

func (r *RateLimiter) cleanup(now time.Time) {
	if now.Sub(r.lastCleanup) < r.cleanupEvery {
		return
	}
	r.lastCleanup = now

	for key, b := range r.buckets {
		b.drain(now)
		if b.value == 0 {
			delete(r.buckets, key)
		}
	}
}
