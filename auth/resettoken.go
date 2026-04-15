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
	// ResetTokenLength is the number of random bytes in a reset token.
	ResetTokenLength = 32

	// DefaultResetTokenLifetime is the default validity period.
	DefaultResetTokenLifetime = 1 * time.Hour
)

// ResetToken represents a password reset token. Like API tokens, the raw
// value is only available at creation time; the store persists a SHA-256 hash.
type ResetToken struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired reports whether the token has passed its expiration time.
func (t *ResetToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// ResetTokenStore is the persistence interface for password reset tokens.
type ResetTokenStore interface {
	CreateResetToken(ctx context.Context, t *ResetToken) error
	GetResetTokenByHash(ctx context.Context, hash string) (*ResetToken, error)
	DeleteResetToken(ctx context.Context, id int64) error
	DeleteResetTokensByUser(ctx context.Context, userID int64) error
}

// ResetTokenManager handles password reset token lifecycle.
type ResetTokenManager struct {
	store    ResetTokenStore
	lifetime time.Duration
}

// ResetTokenOption configures a ResetTokenManager.
type ResetTokenOption func(*ResetTokenManager)

// WithResetTokenLifetime sets the token validity period (default: 1 hour).
func WithResetTokenLifetime(d time.Duration) ResetTokenOption {
	return func(m *ResetTokenManager) { m.lifetime = d }
}

// NewResetTokenManager creates a ResetTokenManager.
func NewResetTokenManager(store ResetTokenStore, opts ...ResetTokenOption) *ResetTokenManager {
	m := &ResetTokenManager{
		store:    store,
		lifetime: DefaultResetTokenLifetime,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Create generates a password reset token for the given user. Returns the
// raw token string which should be sent to the user (e.g. in an email link).
// The store only persists the SHA-256 hash.
func (m *ResetTokenManager) Create(ctx context.Context, userID int64) (rawToken string, token *ResetToken, err error) {
	raw := make([]byte, ResetTokenLength)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating reset token: %w", err)
	}

	rawToken = hex.EncodeToString(raw)
	hash := hashResetToken(rawToken)

	now := time.Now()
	token = &ResetToken{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: now.Add(m.lifetime),
		CreatedAt: now,
	}

	if err := m.store.CreateResetToken(ctx, token); err != nil {
		return "", nil, fmt.Errorf("storing reset token: %w", err)
	}

	return rawToken, token, nil
}

// Validate looks up a raw token, checks expiration, and returns the stored
// record. Returns nil if the token is invalid or expired.
func (m *ResetTokenManager) Validate(ctx context.Context, rawToken string) (*ResetToken, error) {
	hash := hashResetToken(rawToken)

	token, err := m.store.GetResetTokenByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, nil
	}

	return token, nil
}

// Consume validates a token and deletes all tokens for that user in one step.
// This is the typical "reset password" flow: validate the token, then
// invalidate all outstanding reset tokens for that user.
func (m *ResetTokenManager) Consume(ctx context.Context, rawToken string) (*ResetToken, error) {
	token, err := m.Validate(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}

	if err := m.store.DeleteResetTokensByUser(ctx, token.UserID); err != nil {
		return nil, fmt.Errorf("cleaning up reset tokens: %w", err)
	}

	return token, nil
}

func hashResetToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}
