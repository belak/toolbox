package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

// memTokenStore is an in-memory APITokenStore for testing.
type memTokenStore struct {
	tokens map[string]*APIToken // keyed by hash
	nextID int64
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{tokens: make(map[string]*APIToken)}
}

func (m *memTokenStore) CreateAPIToken(_ context.Context, t *APIToken) error {
	m.nextID++
	t.ID = m.nextID
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *memTokenStore) GetAPITokenByHash(_ context.Context, hash string) (*APIToken, error) {
	t, ok := m.tokens[hash]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return t, nil
}

func (m *memTokenStore) UpdateAPITokenLastUsed(_ context.Context, id int64, at time.Time) error {
	for _, t := range m.tokens {
		if t.ID == id {
			t.LastUsedAt = &at
		}
	}
	return nil
}

func (m *memTokenStore) DeleteAPIToken(_ context.Context, id int64) error {
	for k, t := range m.tokens {
		if t.ID == id {
			delete(m.tokens, k)
		}
	}
	return nil
}

func (m *memTokenStore) ListAPITokensByUser(_ context.Context, userID int64) ([]*APIToken, error) {
	var result []*APIToken
	for _, t := range m.tokens {
		if t.UserID == userID {
			result = append(result, t)
		}
	}
	return result, nil
}

func TestAPITokenCreateAndValidate(t *testing.T) {
	store := newMemTokenStore()
	mgr := NewAPITokenManager(store)

	ctx := context.Background()
	raw, token, err := mgr.Create(ctx, 42, "deploy key", nil)
	assert.NoError(t, err)
	assert.True(t, len(raw) > 0)
	assert.Equal(t, "deploy key", token.Name)
	assert.Equal(t, int64(42), token.UserID)

	// Validate with correct raw token.
	got, err := mgr.Validate(ctx, raw)
	assert.NoError(t, err)
	assert.True(t, got != nil)
	assert.Equal(t, token.ID, got.ID)

	// Validate with wrong token.
	_, err = mgr.Validate(ctx, "bt_wrong")
	assert.Error(t, err)
}

func TestAPITokenPrefix(t *testing.T) {
	store := newMemTokenStore()
	mgr := NewAPITokenManager(store, WithTokenPrefix("myapp_"))

	raw, _, err := mgr.Create(context.Background(), 1, "test", nil)
	assert.NoError(t, err)
	assert.True(t, len(raw) > 6)
	assert.Equal(t, "myapp_", raw[:6])
}

func TestAPITokenExpired(t *testing.T) {
	store := newMemTokenStore()
	mgr := NewAPITokenManager(store)

	past := time.Now().Add(-time.Hour)
	raw, _, err := mgr.Create(context.Background(), 1, "expired", &past)
	assert.NoError(t, err)

	got, err := mgr.Validate(context.Background(), raw)
	assert.NoError(t, err)
	assert.Equal(t, (*APIToken)(nil), got)
}

func TestAPITokenDelete(t *testing.T) {
	store := newMemTokenStore()
	mgr := NewAPITokenManager(store)

	ctx := context.Background()
	raw, token, _ := mgr.Create(ctx, 1, "temp", nil)

	assert.NoError(t, mgr.Delete(ctx, token.ID))

	got, err := mgr.Validate(ctx, raw)
	assert.Error(t, err) // not found
	assert.Equal(t, (*APIToken)(nil), got)
}

func TestAPITokenListByUser(t *testing.T) {
	store := newMemTokenStore()
	mgr := NewAPITokenManager(store)

	ctx := context.Background()
	_, _, _ = mgr.Create(ctx, 1, "a", nil)
	_, _, _ = mgr.Create(ctx, 1, "b", nil)
	_, _, _ = mgr.Create(ctx, 2, "c", nil)

	tokens, err := mgr.ListByUser(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(tokens))
}
