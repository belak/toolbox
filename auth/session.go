package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

const (
	// SessionTokenLength is the number of random bytes in a session token.
	SessionTokenLength = 32

	// DefaultSessionLifetime is the default session duration.
	DefaultSessionLifetime = 7 * 24 * time.Hour
)

// Session represents an authenticated session.
type Session struct {
	ID             string
	UserID         int64
	AuthMethod     string // e.g. "password", "oidc"
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastAccessedAt time.Time
}

// IsExpired reports whether the session has passed its expiration time.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionStore is the persistence interface for sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, token string) (*Session, error)
	UpdateSessionAccess(ctx context.Context, token string, at time.Time) error
	DeleteSession(ctx context.Context, token string) error
	DeleteExpiredSessions(ctx context.Context) error
}

// SessionManager handles session lifecycle.
type SessionManager struct {
	store      SessionStore
	cookieName string
	lifetime   time.Duration
	secure     bool // force Secure flag on cookies
}

// SessionOption configures a SessionManager.
type SessionOption func(*SessionManager)

// WithCookieName sets the session cookie name (default: "session").
func WithCookieName(name string) SessionOption {
	return func(m *SessionManager) { m.cookieName = name }
}

// WithSessionLifetime sets the session duration (default: 7 days).
func WithSessionLifetime(d time.Duration) SessionOption {
	return func(m *SessionManager) { m.lifetime = d }
}

// WithSecureCookie forces the Secure flag on session cookies.
func WithSecureCookie(secure bool) SessionOption {
	return func(m *SessionManager) { m.secure = secure }
}

// NewSessionManager creates a SessionManager with the given store and options.
func NewSessionManager(store SessionStore, opts ...SessionOption) *SessionManager {
	m := &SessionManager{
		store:      store,
		cookieName: "session",
		lifetime:   DefaultSessionLifetime,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// CookieName returns the configured cookie name.
func (m *SessionManager) CookieName() string {
	return m.cookieName
}

// Create generates a new session for the given user, persists it, and returns
// the session. The caller is responsible for setting the cookie via SetCookie.
func (m *SessionManager) Create(ctx context.Context, userID int64, authMethod string) (*Session, error) {
	token, err := generateSessionToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	s := &Session{
		ID:             token,
		UserID:         userID,
		AuthMethod:     authMethod,
		CreatedAt:      now,
		ExpiresAt:      now.Add(m.lifetime),
		LastAccessedAt: now,
	}

	if err := m.store.CreateSession(ctx, s); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return s, nil
}

// Get retrieves and validates a session by token. It updates last-accessed
// time on success. Returns nil if the session is missing or expired.
func (m *SessionManager) Get(ctx context.Context, token string) (*Session, error) {
	s, err := m.store.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}
	if s.IsExpired() {
		return nil, nil
	}

	// Best-effort access time update.
	_ = m.store.UpdateSessionAccess(ctx, token, time.Now())

	return s, nil
}

// Delete removes a session.
func (m *SessionManager) Delete(ctx context.Context, token string) error {
	return m.store.DeleteSession(ctx, token)
}

// Cleanup removes all expired sessions.
func (m *SessionManager) Cleanup(ctx context.Context) error {
	return m.store.DeleteExpiredSessions(ctx)
}

// SetCookie writes the session cookie to the response.
func (m *SessionManager) SetCookie(w http.ResponseWriter, s *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    s.ID,
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie removes the session cookie from the response.
func (m *SessionManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   m.cookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// GetFromRequest reads the session token from the request cookie and
// validates it. Returns nil with no error if no cookie is present.
func (m *SessionManager) GetFromRequest(ctx context.Context, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return nil, nil
	}
	return m.Get(ctx, cookie.Value)
}

func generateSessionToken() (string, error) {
	b := make([]byte, SessionTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
