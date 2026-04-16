package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestMiddlewareRequireWithSession(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("sid"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 42, "password", struct{}{})

	mw := NewMiddleware(mgr)

	var gotUserID int64
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(42), gotUserID)
}

func TestMiddlewareRequireNoAuth(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	mw := NewMiddleware(mgr)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestMiddlewareRequireWithBearerToken(t *testing.T) {
	sessionStore := newMemSessionStore()
	sessions := NewSessionManager[struct{}](sessionStore)

	tokenStore := newMemTokenStore()
	tokens := NewAPITokenManager(tokenStore)

	ctx := context.Background()
	raw, _, _ := tokens.Create(ctx, 99, "ci", nil)

	mw := NewMiddleware(sessions, WithAPITokens[struct{}](tokens))

	var gotUserID int64
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(99), gotUserID)
}

func TestMiddlewareOptionalNoAuth(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	mw := NewMiddleware(mgr)

	var gotUserID int64
	handler := mw.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(0), gotUserID)
}

func TestMiddlewareOptionalWithAuth(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("s"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 7, "password", struct{}{})

	mw := NewMiddleware(mgr)

	var gotUserID int64
	handler := mw.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: s.ID})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(7), gotUserID)
}

func TestUserIDFromContextEmpty(t *testing.T) {
	assert.Equal(t, int64(0), UserIDFromContext(context.Background()))
}

func TestMiddlewareCustomUnauthorized(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	mw := NewMiddleware(mgr, WithUnauthorizedHandler[struct{}](func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))

	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSessionFromContext(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[testSessionData](store, WithCookieName("sid"))

	ctx := context.Background()
	data := testSessionData{Theme: "dark", Locale: "en-US"}
	s, _ := mgr.Create(ctx, 42, "password", data)

	mw := NewMiddleware(mgr)

	var gotSession *Session[testSessionData]
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = SessionFromContext[testSessionData](r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, nil, gotSession)
	assert.Equal(t, data, gotSession.Data)
	assert.Equal(t, int64(42), gotSession.UserID)
}

func TestSessionFromContextBearerToken(t *testing.T) {
	sessionStore := newMemSessionStore()
	sessions := NewSessionManager[testSessionData](sessionStore)

	tokenStore := newMemTokenStore()
	tokens := NewAPITokenManager(tokenStore)

	ctx := context.Background()
	raw, _, _ := tokens.Create(ctx, 99, "ci", nil)

	mw := NewMiddleware(sessions, WithAPITokens[testSessionData](tokens))

	var gotSession *Session[testSessionData]
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = SessionFromContext[testSessionData](r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	// Bearer token auth has no session data.
	assert.Equal(t, (*Session[testSessionData])(nil), gotSession)
}
