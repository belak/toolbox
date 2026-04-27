package auth

import (
	"context"
	"net/http"
	"strings"
)

// Resolver loads an authenticated identity from a request. It returns the
// request context (possibly with values attached) plus an ok flag.
//
// Return ok=false with nil error to mean "no authentication present" (the
// request proceeds unauthenticated). Return a non-nil error to mean "lookup
// failed" (the middleware invokes its error handler).
type Resolver func(r *http.Request) (ctx context.Context, ok bool, err error)

// Option configures [Require] and [Optional] middleware.
type Option func(*config)

type config struct {
	onUnauth http.HandlerFunc
	onError  func(http.ResponseWriter, *http.Request, error)
}

// OnUnauthorized sets the handler invoked when the resolver reports no
// authentication. Applies only to [Require]; [Optional] passes
// unauthenticated requests through. Defaults to 401 Unauthorized.
func OnUnauthorized(h http.HandlerFunc) Option {
	return func(c *config) { c.onUnauth = h }
}

// OnError sets the handler invoked when the resolver returns an error.
// Defaults to 500 Internal Server Error.
func OnError(h func(http.ResponseWriter, *http.Request, error)) Option {
	return func(c *config) { c.onError = h }
}

func newConfig(opts []Option) *config {
	c := &config{
		onUnauth: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		},
		onError: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Require returns middleware that rejects unauthenticated requests.
// On error the configured [OnError] handler runs; on missing auth the
// configured [OnUnauthorized] handler runs.
func Require(resolver Resolver, opts ...Option) func(http.Handler) http.Handler {
	c := newConfig(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok, err := resolver(r)
			if err != nil {
				c.onError(w, r, err)
				return
			}
			if !ok {
				c.onUnauth(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Optional returns middleware that attaches the resolved identity to
// the request context when present, and passes unauthenticated
// requests through unchanged. Resolver errors invoke [OnError].
func Optional(resolver Resolver, opts ...Option) func(http.Handler) http.Handler {
	c := newConfig(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok, err := resolver(r)
			if err != nil {
				c.onError(w, r, err)
				return
			}
			if ok {
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SessionResolver builds a [Resolver] that loads a session via cookie and
// stores it in the request context under key. Callers retrieve it with a
// typed helper of their own. The resolver also stamps [KindSession] on
// the context; see [GetKind] / [RequireKind].
func SessionResolver[T any](sessions *SessionManager[T], key any) Resolver {
	return func(r *http.Request) (context.Context, bool, error) {
		s, err := sessions.GetFromRequest(r.Context(), r)
		if err != nil {
			return nil, false, err
		}
		if s == nil {
			return r.Context(), false, nil
		}
		ctx := context.WithValue(r.Context(), key, s)
		ctx = WithKind(ctx, KindSession)
		return ctx, true, nil
	}
}

// BearerTokenResolver builds a [Resolver] that validates an API token from
// the Authorization header and stores it in the request context under key.
// The resolver also stamps [KindBearer] on the context.
func BearerTokenResolver(tokens *APITokenManager, key any) Resolver {
	return func(r *http.Request) (context.Context, bool, error) {
		raw := BearerToken(r)
		if raw == "" {
			return r.Context(), false, nil
		}
		t, err := tokens.Validate(r.Context(), raw)
		if err != nil {
			return nil, false, err
		}
		if t == nil {
			return r.Context(), false, nil
		}
		ctx := context.WithValue(r.Context(), key, t)
		ctx = WithKind(ctx, KindBearer)
		return ctx, true, nil
	}
}

// ChainResolvers returns a [Resolver] that tries each resolver in order and
// returns the first successful result. If every resolver reports
// unauthenticated, the chain reports unauthenticated. The first error short-
// circuits the chain.
func ChainResolvers(rs ...Resolver) Resolver {
	return func(r *http.Request) (context.Context, bool, error) {
		for _, fn := range rs {
			ctx, ok, err := fn(r)
			if err != nil {
				return nil, false, err
			}
			if ok {
				return ctx, true, nil
			}
		}
		return r.Context(), false, nil
	}
}

// BasicAuthTokenResolver builds a [Resolver] that validates an API token
// supplied as the password in HTTP Basic Auth credentials. lookupUser must
// return the user ID for a given username; the resolver confirms the token
// belongs to that user. A mismatch is treated as unauthenticated (ok=false),
// not an error.
func BasicAuthTokenResolver(tokens *APITokenManager, lookupUser func(ctx context.Context, username string) (int64, error), key any) Resolver {
	return func(r *http.Request) (context.Context, bool, error) {
		username, raw, ok := r.BasicAuth()
		if !ok || raw == "" {
			return r.Context(), false, nil
		}
		t, err := tokens.Validate(r.Context(), raw)
		if err != nil {
			return nil, false, err
		}
		if t == nil {
			return r.Context(), false, nil
		}
		userID, err := lookupUser(r.Context(), username)
		if err != nil {
			return nil, false, err
		}
		if t.UserID != userID {
			return r.Context(), false, nil
		}
		ctx := context.WithValue(r.Context(), key, t)
		ctx = WithKind(ctx, KindBasic)
		return ctx, true, nil
	}
}

// RequirePredicate returns middleware that allows the request through
// when check returns true; otherwise invokes onFail (defaults to 403
// Forbidden). Use to gate post-auth requests on application-level
// checks such as admin status, ownership, scopes, or feature flags.
//
// Compose after [AuthMiddleware.Require]: this middleware does not
// itself require authentication.
func RequirePredicate(check func(*http.Request) bool, onFail http.HandlerFunc) func(http.Handler) http.Handler {
	if onFail == nil {
		onFail = func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !check(r) {
				onFail(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BearerToken extracts the token from an "Authorization: Bearer ..." header.
// Returns an empty string if absent or malformed.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return h[7:]
	}
	return ""
}
