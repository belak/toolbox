package auth

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	assert.NoError(t, err)
	assert.NotEqual(t, "", hash)

	assert.True(t, VerifyPassword(hash, "correct-horse-battery"))
	assert.False(t, VerifyPassword(hash, "wrong-password"))
}

func TestHashPasswordDifferentHashes(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	assert.NotEqual(t, h1, h2) // bcrypt salts differ
}
