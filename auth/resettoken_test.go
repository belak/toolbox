package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

// memResetTokenStore is an in-memory ResetTokenStore for testing.
type memResetTokenStore struct {
	tokens map[string]*ResetToken // keyed by hash
	nextID int64
}

func newMemResetTokenStore() *memResetTokenStore {
	return &memResetTokenStore{tokens: make(map[string]*ResetToken)}
}

func (m *memResetTokenStore) CreateResetToken(_ context.Context, t *ResetToken) error {
	m.nextID++
	t.ID = m.nextID
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *memResetTokenStore) GetResetTokenByHash(_ context.Context, hash string) (*ResetToken, error) {
	t, ok := m.tokens[hash]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return t, nil
}

func (m *memResetTokenStore) DeleteResetToken(_ context.Context, id int64) error {
	for k, t := range m.tokens {
		if t.ID == id {
			delete(m.tokens, k)
		}
	}
	return nil
}

func (m *memResetTokenStore) DeleteResetTokensByUser(_ context.Context, userID int64) error {
	for k, t := range m.tokens {
		if t.UserID == userID {
			delete(m.tokens, k)
		}
	}
	return nil
}

func TestResetTokenCreateAndValidate(t *testing.T) {
	store := newMemResetTokenStore()
	mgr := NewResetTokenManager(store)

	ctx := context.Background()
	raw, token, err := mgr.Create(ctx, 42)
	assert.NoError(t, err)
	assert.True(t, len(raw) > 0)
	assert.Equal(t, int64(42), token.UserID)

	got, err := mgr.Validate(ctx, raw)
	assert.NoError(t, err)
	assert.True(t, got != nil)
	assert.Equal(t, token.ID, got.ID)
}

func TestResetTokenExpired(t *testing.T) {
	store := newMemResetTokenStore()
	mgr := NewResetTokenManager(store, WithResetTokenLifetime(0))

	ctx := context.Background()
	raw, _, err := mgr.Create(ctx, 1)
	assert.NoError(t, err)

	got, err := mgr.Validate(ctx, raw)
	assert.NoError(t, err)
	assert.Equal(t, (*ResetToken)(nil), got)
}

func TestResetTokenWrongToken(t *testing.T) {
	store := newMemResetTokenStore()
	mgr := NewResetTokenManager(store)

	ctx := context.Background()
	_, _, _ = mgr.Create(ctx, 1)

	_, err := mgr.Validate(ctx, "wrong-token")
	assert.Error(t, err)
}

func TestResetTokenConsume(t *testing.T) {
	store := newMemResetTokenStore()
	mgr := NewResetTokenManager(store, WithResetTokenLifetime(time.Hour))

	ctx := context.Background()

	// Create two tokens for same user.
	raw1, _, _ := mgr.Create(ctx, 42)
	raw2, _, _ := mgr.Create(ctx, 42)

	// Consume first token.
	got, err := mgr.Consume(ctx, raw1)
	assert.NoError(t, err)
	assert.True(t, got != nil)
	assert.Equal(t, int64(42), got.UserID)

	// Both tokens should now be gone.
	_, err = mgr.Validate(ctx, raw1)
	assert.Error(t, err)
	_, err = mgr.Validate(ctx, raw2)
	assert.Error(t, err)
}

func TestResetTokenConsumeExpired(t *testing.T) {
	store := newMemResetTokenStore()
	mgr := NewResetTokenManager(store, WithResetTokenLifetime(0))

	ctx := context.Background()
	raw, _, _ := mgr.Create(ctx, 1)

	got, err := mgr.Consume(ctx, raw)
	assert.NoError(t, err)
	assert.Equal(t, (*ResetToken)(nil), got)
}
