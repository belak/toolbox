package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// APITokenLength is the number of random bytes in a raw API token.
	APITokenLength = 32

	// APITokenPrefix is prepended to raw tokens for easy identification.
	// Consumers can override this by setting their own prefix.
	APITokenPrefix = "bt_"
)

// APIToken represents a stored API token. The raw token is only available
// at creation time; the store persists the SHA-256 hash.
type APIToken struct {
	ID         int64
	UserID     int64
	Name       string
	TokenHash  string // SHA-256 hex digest
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time // nil = no expiration
}

// IsExpired reports whether the token has passed its expiration time.
func (t *APIToken) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// APITokenStore is the persistence interface for API tokens.
type APITokenStore interface {
	CreateAPIToken(ctx context.Context, t *APIToken) error
	GetAPITokenByHash(ctx context.Context, hash string) (*APIToken, error)
	UpdateAPITokenLastUsed(ctx context.Context, id int64, at time.Time) error
	DeleteAPIToken(ctx context.Context, id int64) error
	ListAPITokensByUser(ctx context.Context, userID int64) ([]*APIToken, error)
}

// APITokenManager handles API token lifecycle.
type APITokenManager struct {
	store  APITokenStore
	prefix string
}

// APITokenOption configures an APITokenManager.
type APITokenOption func(*APITokenManager)

// WithTokenPrefix sets the token prefix (default: "bt_").
func WithTokenPrefix(prefix string) APITokenOption {
	return func(m *APITokenManager) { m.prefix = prefix }
}

// NewAPITokenManager creates an APITokenManager.
func NewAPITokenManager(store APITokenStore, opts ...APITokenOption) *APITokenManager {
	m := &APITokenManager{
		store:  store,
		prefix: APITokenPrefix,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Create generates a new API token for the given user. Returns the raw token
// string (prefix + hex) which must be shown to the user exactly once. The
// stored token only contains the SHA-256 hash.
func (m *APITokenManager) Create(ctx context.Context, userID int64, name string, expiresAt *time.Time) (rawToken string, token *APIToken, err error) {
	raw := make([]byte, APITokenLength)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating token: %w", err)
	}

	rawToken = m.prefix + hex.EncodeToString(raw)
	hash := HashToken(rawToken)

	now := time.Now()
	token = &APIToken{
		UserID:    userID,
		Name:      name,
		TokenHash: hash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	if err := m.store.CreateAPIToken(ctx, token); err != nil {
		return "", nil, fmt.Errorf("storing token: %w", err)
	}

	return rawToken, token, nil
}

// Validate looks up a raw token string, checks expiration, and returns the
// stored token record. Returns nil if invalid or expired.
func (m *APITokenManager) Validate(ctx context.Context, rawToken string) (*APIToken, error) {
	hash := HashToken(rawToken)

	token, err := m.store.GetAPITokenByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, nil
	}

	// Best-effort last-used update.
	_ = m.store.UpdateAPITokenLastUsed(ctx, token.ID, time.Now())

	return token, nil
}

// Delete removes an API token.
func (m *APITokenManager) Delete(ctx context.Context, id int64) error {
	return m.store.DeleteAPIToken(ctx, id)
}

// ListByUser returns all API tokens for a user.
func (m *APITokenManager) ListByUser(ctx context.Context, userID int64) ([]*APIToken, error) {
	return m.store.ListAPITokensByUser(ctx, userID)
}

// HashToken computes the SHA-256 hex digest of a raw token string.
func HashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}
