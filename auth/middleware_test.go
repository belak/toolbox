package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
)

type ctxKey struct{ name string }

var (
	sessionKey = ctxKey{"session"}
	tokenKey   = ctxKey{"token"}
)

func TestRequireAllowsAuthenticated(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("sid"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 42, "password", struct{}{})

	mw := &AuthMiddleware{Resolve: SessionResolver(mgr, sessionKey)}

	var gotUserID int64
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := r.Context().Value(sessionKey).(*Session[struct{}])
		gotUserID = sess.UserID
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(42), gotUserID)
}

func TestRequireRejectsUnauthenticated(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	mw := &AuthMiddleware{Resolve: SessionResolver(mgr, sessionKey)}
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireCustomOnUnauth(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	mw := &AuthMiddleware{
		Resolve: SessionResolver(mgr, sessionKey),
		OnUnauth: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		},
	}
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestRequireResolverError(t *testing.T) {
	boom := errors.New("boom")
	mw := &AuthMiddleware{
		Resolve: func(r *http.Request) (context.Context, bool, error) {
			return nil, false, boom
		},
	}
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequireCustomOnError(t *testing.T) {
	boom := errors.New("boom")
	var gotErr error
	mw := &AuthMiddleware{
		Resolve: func(r *http.Request) (context.Context, bool, error) {
			return nil, false, boom
		},
		OnError: func(w http.ResponseWriter, _ *http.Request, err error) {
			gotErr = err
			http.Error(w, "bad", http.StatusBadGateway)
		},
	}
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Equal(t, boom, gotErr)
}

func TestOptionalPassesThroughUnauthenticated(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store)

	mw := &AuthMiddleware{Resolve: SessionResolver(mgr, sessionKey)}

	var sawSession bool
	handler := mw.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawSession = r.Context().Value(sessionKey).(*Session[struct{}])
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, sawSession)
}

func TestOptionalAttachesWhenAuthenticated(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("s"))

	ctx := context.Background()
	s, _ := mgr.Create(ctx, 7, "password", struct{}{})

	mw := &AuthMiddleware{Resolve: SessionResolver(mgr, sessionKey)}

	var gotUserID int64
	handler := mw.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sess, ok := r.Context().Value(sessionKey).(*Session[struct{}]); ok {
			gotUserID = sess.UserID
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: s.ID})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(7), gotUserID)
}

func TestChainResolversFirstWins(t *testing.T) {
	sessionStore := newMemSessionStore()
	sessions := NewSessionManager[struct{}](sessionStore, WithCookieName("sid"))

	tokenStore := newMemTokenStore()
	tokens := NewAPITokenManager(tokenStore)

	ctx := context.Background()
	raw, _, _ := tokens.Create(ctx, 99, "ci", nil)

	mw := &AuthMiddleware{
		Resolve: ChainResolvers(
			SessionResolver(sessions, sessionKey),
			BearerTokenResolver(tokens, tokenKey),
		),
	}

	var gotToken *APIToken
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, _ = r.Context().Value(tokenKey).(*APIToken)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, nil, gotToken)
	assert.Equal(t, int64(99), gotToken.UserID)
}

func TestChainResolversAllUnauthenticated(t *testing.T) {
	store := newMemSessionStore()
	sessions := NewSessionManager[struct{}](store)
	tokens := NewAPITokenManager(newMemTokenStore())

	mw := &AuthMiddleware{
		Resolve: ChainResolvers(
			SessionResolver(sessions, sessionKey),
			BearerTokenResolver(tokens, tokenKey),
		),
	}
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"},
		{"BEARER abc123", "abc123"},
		{"Basic foo", ""},
		{"Bearer", ""},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		assert.Equal(t, tc.want, BearerToken(r))
	}
}
