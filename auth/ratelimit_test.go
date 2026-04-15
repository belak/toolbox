package auth

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(3, time.Hour)

	assert.True(t, rl.Allow("user:alice"))
	assert.True(t, rl.Allow("user:alice"))
	assert.True(t, rl.Allow("user:alice"))  // 3rd allowed (rate=3)
	assert.False(t, rl.Allow("user:alice")) // 4th rejected

	// Different key should be independent.
	assert.True(t, rl.Allow("user:bob"))
}

func TestRateLimiterCheck(t *testing.T) {
	rl := NewRateLimiter(2, time.Hour)

	assert.True(t, rl.Check("key"))
	assert.True(t, rl.Allow("key"))
	assert.True(t, rl.Check("key")) // check doesn't consume
	assert.True(t, rl.Allow("key")) // but allow does
	assert.False(t, rl.Check("key"))
	assert.False(t, rl.Allow("key"))
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(2, time.Hour)

	rl.Allow("key")
	rl.Allow("key")
	assert.False(t, rl.Allow("key"))

	rl.Reset("key")
	assert.True(t, rl.Allow("key"))
}

func TestRateLimiterAllowN(t *testing.T) {
	rl := NewRateLimiter(10, time.Hour)

	assert.True(t, rl.AllowN("key", 5))
	assert.True(t, rl.AllowN("key", 4))
	assert.False(t, rl.AllowN("key", 2)) // 9+2=11 > 10, rejected
	assert.True(t, rl.AllowN("key", 1))  // 9+1=10 = rate, allowed
	assert.False(t, rl.AllowN("key", 1)) // 10+1=11 > 10, rejected
}

func TestRateLimiterDrain(t *testing.T) {
	// Use a very short period so drain happens fast.
	rl := NewRateLimiter(2, 100*time.Millisecond)

	assert.True(t, rl.Allow("key"))
	assert.True(t, rl.Allow("key"))
	assert.False(t, rl.Allow("key"))

	// Wait for bucket to drain.
	time.Sleep(150 * time.Millisecond)

	assert.True(t, rl.Allow("key"))
}
