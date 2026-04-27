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

	var gotUserID int64
	handler := Require(SessionResolver(mgr, sessionKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := Require(SessionResolver(mgr, sessionKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := Require(
		SessionResolver(mgr, sessionKey),
		OnUnauthorized(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestRequireResolverError(t *testing.T) {
	boom := errors.New("boom")
	resolver := func(r *http.Request) (context.Context, bool, error) {
		return nil, false, boom
	}
	handler := Require(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	resolver := func(r *http.Request) (context.Context, bool, error) {
		return nil, false, boom
	}
	handler := Require(resolver,
		OnError(func(w http.ResponseWriter, _ *http.Request, err error) {
			gotErr = err
			http.Error(w, "bad", http.StatusBadGateway)
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	var sawSession bool
	handler := Optional(SessionResolver(mgr, sessionKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	var gotUserID int64
	handler := Optional(SessionResolver(mgr, sessionKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	resolver := ChainResolvers(
		SessionResolver(sessions, sessionKey),
		BearerTokenResolver(tokens, tokenKey),
	)
	var gotToken *APIToken
	handler := Require(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	resolver := ChainResolvers(
		SessionResolver(sessions, sessionKey),
		BearerTokenResolver(tokens, tokenKey),
	)
	handler := Require(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthTokenResolverValid(t *testing.T) {
	store := newMemTokenStore()
	tokens := NewAPITokenManager(store)

	ctx := context.Background()
	raw, _, _ := tokens.Create(ctx, 42, "webdav", nil)

	lookup := func(_ context.Context, username string) (int64, error) {
		if username == "alice" {
			return 42, nil
		}
		return 0, errors.New("not found")
	}

	var gotToken *APIToken
	handler := Require(BasicAuthTokenResolver(tokens, lookup, tokenKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, _ = r.Context().Value(tokenKey).(*APIToken)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dav/", nil)
	req.SetBasicAuth("alice", raw)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, nil, gotToken)
	assert.Equal(t, int64(42), gotToken.UserID)
}

func TestBasicAuthTokenResolverNoHeader(t *testing.T) {
	tokens := NewAPITokenManager(newMemTokenStore())
	lookup := func(_ context.Context, _ string) (int64, error) {
		t.Fatal("lookupUser should not be called")
		return 0, nil
	}

	handler := Require(BasicAuthTokenResolver(tokens, lookup, tokenKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/dav/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthTokenResolverWrongUsername(t *testing.T) {
	store := newMemTokenStore()
	tokens := NewAPITokenManager(store)

	ctx := context.Background()
	// Token belongs to user 42, but we look up "eve" who is user 99.
	raw, _, _ := tokens.Create(ctx, 42, "webdav", nil)

	lookup := func(_ context.Context, username string) (int64, error) {
		if username == "eve" {
			return 99, nil
		}
		return 0, errors.New("not found")
	}

	handler := Require(BasicAuthTokenResolver(tokens, lookup, tokenKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/dav/", nil)
	req.SetBasicAuth("eve", raw)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthTokenResolverLookupError(t *testing.T) {
	store := newMemTokenStore()
	tokens := NewAPITokenManager(store)

	ctx := context.Background()
	raw, _, _ := tokens.Create(ctx, 1, "webdav", nil)

	boom := errors.New("db down")
	lookup := func(_ context.Context, _ string) (int64, error) {
		return 0, boom
	}

	handler := Require(BasicAuthTokenResolver(tokens, lookup, tokenKey))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/dav/", nil)
	req.SetBasicAuth("alice", raw)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSessionResolverStampsKind(t *testing.T) {
	store := newMemSessionStore()
	mgr := NewSessionManager[struct{}](store, WithCookieName("sid"))
	ctx := context.Background()
	s, _ := mgr.Create(ctx, 1, "password", struct{}{})

	resolver := SessionResolver(mgr, sessionKey)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID})

	gotCtx, ok, err := resolver(req)
	assert.NoError(t, err)
	assert.True(t, ok)
	k, present := GetKind(gotCtx)
	assert.True(t, present)
	assert.Equal(t, KindSession, k)
}

func TestBearerTokenResolverStampsKind(t *testing.T) {
	tokens := NewAPITokenManager(newMemTokenStore())
	raw, _, _ := tokens.Create(context.Background(), 1, "ci", nil)

	resolver := BearerTokenResolver(tokens, tokenKey)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)

	gotCtx, ok, err := resolver(req)
	assert.NoError(t, err)
	assert.True(t, ok)
	k, present := GetKind(gotCtx)
	assert.True(t, present)
	assert.Equal(t, KindBearer, k)
}

func TestBasicAuthTokenResolverStampsKind(t *testing.T) {
	tokens := NewAPITokenManager(newMemTokenStore())
	raw, _, _ := tokens.Create(context.Background(), 42, "webdav", nil)
	lookup := func(_ context.Context, _ string) (int64, error) { return 42, nil }

	resolver := BasicAuthTokenResolver(tokens, lookup, tokenKey)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", raw)

	gotCtx, ok, err := resolver(req)
	assert.NoError(t, err)
	assert.True(t, ok)
	k, present := GetKind(gotCtx)
	assert.True(t, present)
	assert.Equal(t, KindBasic, k)
}

func TestRequireKindAllows(t *testing.T) {
	mw := RequireKind(nil, KindSession)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(WithKind(context.Background(), KindSession))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireKindRejectsMissing(t *testing.T) {
	mw := RequireKind(nil, KindSession)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireKindRejectsWrongKind(t *testing.T) {
	mw := RequireKind(nil, KindSession)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(WithKind(context.Background(), KindBearer))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireKindMultipleAllowed(t *testing.T) {
	mw := RequireKind(nil, KindBearer, KindBasic)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, k := range []Kind{KindBearer, KindBasic} {
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(WithKind(context.Background(), k))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "kind %s should be allowed", k)
	}
}

func TestRequireKindCustomOnFail(t *testing.T) {
	mw := RequireKind(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}, KindSession)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTeapot, w.Code)
}

func TestRequirePredicateAllows(t *testing.T) {
	mw := RequirePredicate(func(*http.Request) bool { return true }, nil)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.True(t, called)
}

func TestRequirePredicateRejectsDefault(t *testing.T) {
	mw := RequirePredicate(func(*http.Request) bool { return false }, nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePredicateCustomOnFail(t *testing.T) {
	mw := RequirePredicate(
		func(*http.Request) bool { return false },
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		},
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
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
