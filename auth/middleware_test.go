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
	mgr := NewSessionManager(store, WithCookieName("sid"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 42, "password")

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
	mgr := NewSessionManager(store)

	mw := NewMiddleware(mgr)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code) // redirect to /login
}

func TestMiddlewareRequireWithBearerToken(t *testing.T) {
	sessionStore := newMemSessionStore()
	sessions := NewSessionManager(sessionStore)

	tokenStore := newMemTokenStore()
	tokens := NewAPITokenManager(tokenStore)

	ctx := context.Background()
	raw, _, _ := tokens.Create(ctx, 99, "ci", nil)

	mw := NewMiddleware(sessions, WithAPITokens(tokens))

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
	mgr := NewSessionManager(store)

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
	assert.Equal(t, int64(0), gotUserID) // no user
}

func TestMiddlewareOptionalWithAuth(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager(store, WithCookieName("s"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 7, "password")

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
	mgr := NewSessionManager(store)

	mw := NewMiddleware(mgr, WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request) {
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
