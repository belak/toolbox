// Package auth provides reusable authentication primitives: password hashing,
// session management, OIDC login, and API token support. It defines storage
// interfaces that consumers implement with their own database layer.
package auth

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// getBcryptCost returns cost 4 during tests (fast) and DefaultCost (10) in
// production.
func getBcryptCost() int {
	if testing.Testing() {
		return 4
	}
	return bcrypt.DefaultCost
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), getBcryptCost())
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks if a plaintext password matches a bcrypt hash.
func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
