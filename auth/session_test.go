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
	sessions map[string]*SessionRecord
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: make(map[string]*SessionRecord)}
}

func (m *memSessionStore) CreateSession(_ context.Context, s *SessionRecord) error {
	m.sessions[s.ID] = s
	return nil
}

func (m *memSessionStore) GetSession(_ context.Context, token string) (*SessionRecord, error) {
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

func (m *memSessionStore) ListSessionsByUser(_ context.Context, userID int64) ([]*SessionRecord, error) {
	var out []*SessionRecord
	for _, s := range m.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *memSessionStore) DeleteSession(_ context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}

func (m *memSessionStore) DeleteSessionsByUser(_ context.Context, userID int64) error {
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
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

type testSessionData struct {
	Theme  string `json:"theme,omitempty"`
	Locale string `json:"locale,omitempty"`
}

func TestSessionCreateAndGet(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("test_session"))

	ctx := context.Background()
	s, err := mgr.Create(ctx, 42, "password", struct{}{})
	assert.NoError(t, err)
	assert.NotEqual(t, "", s.ID)
	assert.Equal(t, int64(42), s.UserID)
	assert.Equal(t, "password", s.AuthMethod)

	got, err := mgr.Get(ctx, s.ID)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, got)
	assert.Equal(t, s.UserID, got.UserID)
}

func TestSessionDataRoundTrip(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[testSessionData](store)

	ctx := context.Background()
	data := testSessionData{Theme: "dark", Locale: "en-US"}
	s, err := mgr.Create(ctx, 1, "password", data)
	assert.NoError(t, err)
	assert.Equal(t, data, s.Data)

	got, err := mgr.Get(ctx, s.ID)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, got)
	assert.Equal(t, data, got.Data)
}

func TestSessionExpired(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithSessionLifetime(0))

	ctx := context.Background()
	s, err := mgr.Create(ctx, 1, "password", struct{}{})
	assert.NoError(t, err)

	got, err := mgr.Get(ctx, s.ID)
	assert.NoError(t, err)
	assert.Equal(t, (*Session[struct{}])(nil), got)
}

func TestSessionDelete(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 1, "password", struct{}{})

	assert.NoError(t, mgr.Delete(ctx, s.ID))

	got, _ := mgr.Get(ctx, s.ID)
	assert.Equal(t, (*Session[struct{}])(nil), got)
}

func TestSessionListByUser(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	ctx := context.Background()
	s1, _ := mgr.Create(ctx, 1, "password", struct{}{})
	s2, _ := mgr.Create(ctx, 1, "oidc", struct{}{})
	_, _ = mgr.Create(ctx, 2, "password", struct{}{})

	got, err := mgr.ListByUser(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(got))

	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	assert.True(t, ids[s1.ID])
	assert.True(t, ids[s2.ID])
}

func TestSessionListByUserSkipsExpired(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)
	expiredMgr := NewSessionManager[struct{}](store, WithSessionLifetime(0))

	ctx := context.Background()
	live, _ := mgr.Create(ctx, 1, "password", struct{}{})
	_, _ = expiredMgr.Create(ctx, 1, "password", struct{}{})

	got, err := mgr.ListByUser(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(got))
	assert.Equal(t, live.ID, got[0].ID)
}

func TestSessionDeleteAllByUser(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	ctx := context.Background()
	_, _ = mgr.Create(ctx, 1, "password", struct{}{})
	_, _ = mgr.Create(ctx, 1, "oidc", struct{}{})
	other, _ := mgr.Create(ctx, 2, "password", struct{}{})

	assert.NoError(t, mgr.DeleteAllByUser(ctx, 1))

	got, _ := mgr.ListByUser(ctx, 1)
	assert.Equal(t, 0, len(got))

	// Other user's session untouched.
	s, err := mgr.Get(ctx, other.ID)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, s)
}

func TestSessionCookie(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("myapp"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 1, "password", struct{}{})

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
	mgr := NewSessionManager[struct{}](store, WithCookieName("sid"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 99, "oidc", struct{}{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID})

	got, err := mgr.GetFromRequest(ctx, req)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, got)
	assert.Equal(t, int64(99), got.UserID)
}

func TestGetFromRequestNoCookie(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := mgr.GetFromRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, (*Session[struct{}])(nil), got)
}
