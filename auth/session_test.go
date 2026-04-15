package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

// memSessionStore is an in-memory SessionStore for testing.
type memSessionStore struct {
	sessions map[string]*Session
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: make(map[string]*Session)}
}

func (m *memSessionStore) CreateSession(_ context.Context, s *Session) error {
	m.sessions[s.ID] = s
	return nil
}

func (m *memSessionStore) GetSession(_ context.Context, token string) (*Session, error) {
	s, ok := m.sessions[token]
	if !ok {
		return nil, context.Canceled // stand-in for "not found"
	}
	return s, nil
}

func (m *memSessionStore) UpdateSessionAccess(_ context.Context, token string, at time.Time) error {
	if s, ok := m.sessions[token]; ok {
		s.LastAccessedAt = at
	}
	return nil
}

func (m *memSessionStore) DeleteSession(_ context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}

func (m *memSessionStore) DeleteExpiredSessions(_ context.Context) error {
	now := time.Now()
	for k, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, k)
		}
	}
	return nil
}

func TestSessionCreateAndGet(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store, WithCookieName("test_session"))

	ctx := context.Background()
	s, err := mgr.Create(ctx, 42, "password")
	assert.NoError(t, err)
	assert.NotEqual(t, "", s.ID)
	assert.Equal(t, int64(42), s.UserID)
	assert.Equal(t, "password", s.AuthMethod)

	got, err := mgr.Get(ctx, s.ID)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, got)
	assert.Equal(t, s.UserID, got.UserID)
}

func TestSessionExpired(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store, WithSessionLifetime(0)) // expires immediately

	ctx := context.Background()
	s, err := mgr.Create(ctx, 1, "password")
	assert.NoError(t, err)

	// Session expires at creation time (lifetime=0), so it should be nil.
	got, err := mgr.Get(ctx, s.ID)
	assert.NoError(t, err)
	assert.Equal(t, (*Session)(nil), got)
}

func TestSessionDelete(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store)

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 1, "password")

	assert.NoError(t, mgr.Delete(ctx, s.ID))

	got, _ := mgr.Get(ctx, s.ID)
	assert.Equal(t, (*Session)(nil), got)
}

func TestSessionCookie(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store, WithCookieName("myapp"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 1, "password")

	w := httptest.NewRecorder()
	mgr.SetCookie(w, s)

	cookies := w.Result().Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, "myapp", cookies[0].Name)
	assert.Equal(t, s.ID, cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
}

func TestGetFromRequest(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store, WithCookieName("sid"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 99, "oidc")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID})

	got, err := mgr.GetFromRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, got)
	assert.Equal(t, int64(99), got.UserID)
}

func TestGetFromRequestNoCookie(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := mgr.GetFromRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, (*Session)(nil), got)
}
