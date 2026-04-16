package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const (
	userContextKey    contextKey = "auth_user_id"
	sessionContextKey contextKey = "auth_session"
)

// Middleware authenticates requests via session cookie or Bearer token.
// On success it stores the user ID in the context, accessible via
// UserIDFromContext. When session auth is used, the full session is also
// available via SessionFromContext.
type Middleware[T any] struct {
	sessions *SessionManager[T]
	tokens   *APITokenManager
	onUnauth http.HandlerFunc
}

// MiddlewareOption configures the auth [Middleware].
type MiddlewareOption[T any] func(*Middleware[T])

// WithAPITokens enables Bearer token authentication.
func WithAPITokens[T any](m *APITokenManager) MiddlewareOption[T] {
	return func(mw *Middleware[T]) { mw.tokens = m }
}

// WithUnauthorizedHandler sets the handler called when authentication fails.
// Default redirects to /login.
func WithUnauthorizedHandler[T any](h http.HandlerFunc) MiddlewareOption[T] {
	return func(mw *Middleware[T]) { mw.onUnauth = h }
}

// NewMiddleware creates auth middleware that checks sessions and optionally
// API tokens.
func NewMiddleware[T any](sessions *SessionManager[T], opts ...MiddlewareOption[T]) *Middleware[T] {
	mw := &Middleware[T]{
		sessions: sessions,
		onUnauth: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		},
	}
	for _, o := range opts {
		o(mw)
	}
	return mw
}

// Require returns middleware that rejects unauthenticated requests.
func (mw *Middleware[T]) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, userID, ok := mw.authenticate(r)
		if !ok {
			mw.sessions.ClearCookie(w)
			mw.onUnauth(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, userID)
		if session != nil {
			ctx = context.WithValue(ctx, sessionContextKey, session)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Optional returns middleware that populates the user context if
// authenticated but does not reject unauthenticated requests.
func (mw *Middleware[T]) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if session, userID, ok := mw.authenticate(r); ok {
			ctx := context.WithValue(r.Context(), userContextKey, userID)
			if session != nil {
				ctx = context.WithValue(ctx, sessionContextKey, session)
			}
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate tries session cookie first, then Bearer token.
func (mw *Middleware[T]) authenticate(r *http.Request) (*Session[T], int64, bool) {
	// Try session cookie.
	session, err := mw.sessions.GetFromRequest(r.Context(), r)
	if err == nil && session != nil {
		return session, session.UserID, true
	}

	// Try Bearer token.
	if mw.tokens != nil {
		if raw := bearerToken(r); raw != "" {
			token, err := mw.tokens.Validate(r.Context(), raw)
			if err == nil && token != nil {
				return nil, token.UserID, true
			}
		}
	}

	return nil, 0, false
}

// UserIDFromContext returns the authenticated user ID, or 0 if not
// authenticated.
func UserIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(userContextKey).(int64)
	return id
}

// SessionFromContext returns the authenticated session, or nil if the
// request was not authenticated via a session (e.g. Bearer token auth).
func SessionFromContext[T any](ctx context.Context) *Session[T] {
	s, _ := ctx.Value(sessionContextKey).(*Session[T])
	return s
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
