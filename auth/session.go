package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

// SessionRecord is the storage representation of a session. Store
// implementations work with this type; the generic [Session] is used by
// application code.
type SessionRecord struct {
	ID             string
	UserID         int64
	AuthMethod     string
	Data           json.RawMessage
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastAccessedAt time.Time
}

// IsExpired reports whether the session has passed its expiration time.
func (s *SessionRecord) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Session represents an authenticated session with typed application data.
type Session[T any] struct {
	ID             string
	UserID         int64
	AuthMethod     string
	Data           T
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastAccessedAt time.Time
}

// SessionStore is the persistence interface for sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, s *SessionRecord) error
	GetSession(ctx context.Context, token string) (*SessionRecord, error)
	UpdateSessionAccess(ctx context.Context, token string, at time.Time) error
	DeleteSession(ctx context.Context, token string) error
	DeleteExpiredSessions(ctx context.Context) error
}

type sessionConfig struct {
	cookieName string
	lifetime   time.Duration
	secure     bool
}

// SessionOption configures a [SessionManager].
type SessionOption func(*sessionConfig)

// WithCookieName sets the session cookie name (default: "session").
func WithCookieName(name string) SessionOption {
	return func(c *sessionConfig) { c.cookieName = name }
}

// WithSessionLifetime sets the session duration (default: 7 days).
func WithSessionLifetime(d time.Duration) SessionOption {
	return func(c *sessionConfig) { c.lifetime = d }
}

// WithSecureCookie forces the Secure flag on session cookies.
func WithSecureCookie(secure bool) SessionOption {
	return func(c *sessionConfig) { c.secure = secure }
}

// SessionManager handles session lifecycle with typed session data.
type SessionManager[T any] struct {
	store      SessionStore
	cookieName string
	lifetime   time.Duration
	secure     bool
}

// NewSessionManager creates a SessionManager with the given store and options.
func NewSessionManager[T any](store SessionStore, opts ...SessionOption) *SessionManager[T] {
	cfg := &sessionConfig{
		cookieName: "session",
		lifetime:   DefaultSessionLifetime,
	}
	for _, o := range opts {
		o(cfg)
	}
	return &SessionManager[T]{
		store:      store,
		cookieName: cfg.cookieName,
		lifetime:   cfg.lifetime,
		secure:     cfg.secure,
	}
}

// CookieName returns the configured cookie name.
func (m *SessionManager[T]) CookieName() string {
	return m.cookieName
}

// Create generates a new session for the given user, persists it, and
// returns the session. The caller is responsible for setting the cookie
// via SetCookie.
func (m *SessionManager[T]) Create(ctx context.Context, userID int64, authMethod string, data T) (*Session[T], error) {
	token, err := generateSessionToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	s := &Session[T]{
		ID:             token,
		UserID:         userID,
		AuthMethod:     authMethod,
		Data:           data,
		CreatedAt:      now,
		ExpiresAt:      now.Add(m.lifetime),
		LastAccessedAt: now,
	}

	rec, err := sessionToRecord(s)
	if err != nil {
		return nil, err
	}

	if err := m.store.CreateSession(ctx, rec); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return s, nil
}

// Get retrieves and validates a session by token. It updates last-accessed
// time on success. Returns nil if the session is missing or expired.
func (m *SessionManager[T]) Get(ctx context.Context, token string) (*Session[T], error) {
	rec, err := m.store.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}
	if rec.IsExpired() {
		return nil, nil
	}

	s, err := recordToSession[T](rec)
	if err != nil {
		return nil, err
	}

	// Best-effort access time update.
	_ = m.store.UpdateSessionAccess(ctx, token, time.Now())

	return s, nil
}

// Delete removes a session.
func (m *SessionManager[T]) Delete(ctx context.Context, token string) error {
	return m.store.DeleteSession(ctx, token)
}

// Cleanup removes all expired sessions.
func (m *SessionManager[T]) Cleanup(ctx context.Context) error {
	return m.store.DeleteExpiredSessions(ctx)
}

// SetCookie writes the session cookie to the response.
func (m *SessionManager[T]) SetCookie(w http.ResponseWriter, s *Session[T]) {
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
func (m *SessionManager[T]) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   m.cookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// GetFromRequest reads the session token from the request cookie and
// validates it. Returns nil with no error if no cookie is present.
func (m *SessionManager[T]) GetFromRequest(ctx context.Context, r *http.Request) (*Session[T], error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return nil, nil
	}
	return m.Get(ctx, cookie.Value)
}

func recordToSession[T any](r *SessionRecord) (*Session[T], error) {
	s := &Session[T]{
		ID:             r.ID,
		UserID:         r.UserID,
		AuthMethod:     r.AuthMethod,
		CreatedAt:      r.CreatedAt,
		ExpiresAt:      r.ExpiresAt,
		LastAccessedAt: r.LastAccessedAt,
	}
	if len(r.Data) > 0 {
		if err := json.Unmarshal(r.Data, &s.Data); err != nil {
			return nil, fmt.Errorf("unmarshaling session data: %w", err)
		}
	}
	return s, nil
}

func sessionToRecord[T any](s *Session[T]) (*SessionRecord, error) {
	data, err := json.Marshal(s.Data)
	if err != nil {
		return nil, fmt.Errorf("marshaling session data: %w", err)
	}
	return &SessionRecord{
		ID:             s.ID,
		UserID:         s.UserID,
		AuthMethod:     s.AuthMethod,
		Data:           data,
		CreatedAt:      s.CreatedAt,
		ExpiresAt:      s.ExpiresAt,
		LastAccessedAt: s.LastAccessedAt,
	}, nil
}

func generateSessionToken() (string, error) {
	b := make([]byte, SessionTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
