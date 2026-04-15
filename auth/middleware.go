package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const userContextKey contextKey = "auth_user_id"

// Middleware authenticates requests via session cookie or Bearer token.
// On success it stores the user ID in the context, accessible via
// UserIDFromContext. On failure it calls the provided onUnauth handler.
type Middleware struct {
	sessions *SessionManager
	tokens   *APITokenManager // nil if API tokens not enabled
	onUnauth http.HandlerFunc
}

// MiddlewareOption configures the auth Middleware.
type MiddlewareOption func(*Middleware)

// WithAPITokens enables Bearer token authentication.
func WithAPITokens(m *APITokenManager) MiddlewareOption {
	return func(mw *Middleware) { mw.tokens = m }
}

// WithUnauthorizedHandler sets the handler called when authentication fails.
// Default redirects to /login.
func WithUnauthorizedHandler(h http.HandlerFunc) MiddlewareOption {
	return func(mw *Middleware) { mw.onUnauth = h }
}

// NewMiddleware creates auth middleware that checks sessions and optionally
// API tokens.
func NewMiddleware(sessions *SessionManager, opts ...MiddlewareOption) *Middleware {
	mw := &Middleware{
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
func (mw *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := mw.authenticate(r)
		if !ok {
			mw.sessions.ClearCookie(w)
			mw.onUnauth(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Optional returns middleware that populates the user context if
// authenticated but does not reject unauthenticated requests.
func (mw *Middleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userID, ok := mw.authenticate(r); ok {
			ctx := context.WithValue(r.Context(), userContextKey, userID)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate tries session cookie first, then Bearer token.
func (mw *Middleware) authenticate(r *http.Request) (int64, bool) {
	// Try session cookie.
	session, err := mw.sessions.GetFromRequest(r.Context(), r)
	if err == nil && session != nil {
		return session.UserID, true
	}

	// Try Bearer token.
	if mw.tokens != nil {
		if raw := bearerToken(r); raw != "" {
			token, err := mw.tokens.Validate(r.Context(), raw)
			if err == nil && token != nil {
				return token.UserID, true
			}
		}
	}

	return 0, false
}

// UserIDFromContext returns the authenticated user ID, or 0 if not
// authenticated.
func UserIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(userContextKey).(int64)
	return id
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
