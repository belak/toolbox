package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// StateExpiry is how long an OIDC state parameter is valid.
	StateExpiry = 10 * time.Minute
)

// OIDCIdentity represents a linked OIDC account.
type OIDCIdentity struct {
	ID          int64
	UserID      int64
	Issuer      string
	Subject     string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// OIDCIdentityStore is the persistence interface for OIDC identities.
type OIDCIdentityStore interface {
	GetOIDCIdentity(ctx context.Context, issuer, subject string) (*OIDCIdentity, error)
	GetOIDCIdentitiesByUserID(ctx context.Context, userID int64) ([]*OIDCIdentity, error)
	CreateOIDCIdentity(ctx context.Context, id *OIDCIdentity) error
	UpdateOIDCLastLogin(ctx context.Context, id int64, at time.Time) error
	DeleteOIDCIdentity(ctx context.Context, id int64) error
}

// OIDCConfig holds the settings needed to connect to an OIDC provider.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string // additional scopes beyond openid, profile, email
}

// resolvedProvider holds the lazily-initialized OIDC provider state.
type resolvedProvider struct {
	provider *oidc.Provider
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// OIDCService handles OIDC authentication flows for a single provider.
// Provider discovery is deferred to first use so the application can start
// even when the OIDC provider is unreachable.
type OIDCService struct {
	config OIDCConfig
	secret []byte
	store  OIDCIdentityStore
	logger *slog.Logger

	// Lazy init: resolved is populated on first call to resolve().
	mu       sync.Mutex
	resolved *resolvedProvider
}

// OIDCServiceOption configures an OIDCService.
type OIDCServiceOption func(*OIDCService)

// WithOIDCLogger sets the logger for OIDC operations.
func WithOIDCLogger(l *slog.Logger) OIDCServiceOption {
	return func(s *OIDCService) { s.logger = l }
}

// NewOIDCService creates an OIDCService. Provider discovery is not performed
// until the first authentication attempt, so this always succeeds.
//
// The secret is used to HMAC-sign state parameters. The store handles
// identity persistence (pass nil if not needed).
func NewOIDCService(cfg OIDCConfig, secret []byte, store OIDCIdentityStore, opts ...OIDCServiceOption) *OIDCService {
	s := &OIDCService{
		config: cfg,
		secret: secret,
		store:  store,
		logger: slog.Default(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// resolve performs lazy provider discovery. Returns the cached result on
// subsequent calls, or retries if the previous attempt failed.
func (s *OIDCService) resolve(ctx context.Context) (*resolvedProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.resolved != nil {
		return s.resolved, nil
	}

	provider, err := oidc.NewProvider(ctx, s.config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", s.config.IssuerURL, err)
	}

	scopes := []string{"openid", "profile", "email"}
	scopes = append(scopes, s.config.Scopes...)

	oauth2Config := oauth2.Config{
		ClientID:     s.config.ClientID,
		ClientSecret: s.config.ClientSecret,
		RedirectURL:  s.config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: s.config.ClientID})

	s.resolved = &resolvedProvider{
		provider: provider,
		oauth2:   oauth2Config,
		verifier: verifier,
	}

	s.logger.Info("OIDC provider discovered", "issuer", s.config.IssuerURL)
	return s.resolved, nil
}

// Ready reports whether provider discovery has completed successfully.
func (s *OIDCService) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolved != nil
}

// IssuerURL returns the configured issuer URL.
func (s *OIDCService) IssuerURL() string {
	return s.config.IssuerURL
}

// GenerateState creates a signed state parameter for CSRF protection.
// flow identifies the purpose (e.g. "login", "link").
func (s *OIDCService) GenerateState(flow string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s|%s|%d",
		flow,
		base64.RawURLEncoding.EncodeToString(nonce),
		timestamp,
	)

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)

	state := fmt.Sprintf("%s|%s", payload, base64.RawURLEncoding.EncodeToString(sig))
	return base64.RawURLEncoding.EncodeToString([]byte(state)), nil
}

// VerifyState verifies a state parameter and returns the flow string.
func (s *OIDCService) VerifyState(state string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", fmt.Errorf("invalid state encoding")
	}

	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid state format")
	}

	flow := parts[0]
	payload := strings.Join(parts[:3], "|")

	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", fmt.Errorf("invalid state signature")
	}

	timestamp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid state timestamp: %w", err)
	}
	if time.Now().Unix()-timestamp > int64(StateExpiry.Seconds()) {
		return "", fmt.Errorf("state expired")
	}

	return flow, nil
}

// AuthCodeURL returns the authorization URL and a PKCE verifier. The caller
// must persist the verifier (e.g. in a cookie) and pass it to Exchange.
// Triggers provider discovery if not yet resolved.
func (s *OIDCService) AuthCodeURL(ctx context.Context, state string) (authURL, verifier string, err error) {
	r, err := s.resolve(ctx)
	if err != nil {
		return "", "", err
	}
	verifier = oauth2.GenerateVerifier()
	authURL = r.oauth2.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return authURL, verifier, nil
}

// Exchange trades an authorization code for verified ID token claims.
// The verifier must be the value returned by AuthCodeURL for this flow.
// Triggers provider discovery if not yet resolved.
func (s *OIDCService) Exchange(ctx context.Context, code, verifier string) (map[string]any, error) {
	r, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}

	token, err := r.oauth2.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := r.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	return claims, nil
}

// Identity persistence helpers. These delegate to the store.

// GetIdentity retrieves an OIDC identity by issuer and subject.
func (s *OIDCService) GetIdentity(ctx context.Context, issuer, subject string) (*OIDCIdentity, error) {
	return s.store.GetOIDCIdentity(ctx, issuer, subject)
}

// GetIdentitiesByUserID retrieves all OIDC identities for a user.
func (s *OIDCService) GetIdentitiesByUserID(ctx context.Context, userID int64) ([]*OIDCIdentity, error) {
	return s.store.GetOIDCIdentitiesByUserID(ctx, userID)
}

// CreateIdentity links an OIDC identity to a user.
func (s *OIDCService) CreateIdentity(ctx context.Context, userID int64, issuer, subject string) (*OIDCIdentity, error) {
	now := time.Now()
	id := &OIDCIdentity{
		UserID:      userID,
		Issuer:      issuer,
		Subject:     subject,
		CreatedAt:   now,
		LastLoginAt: now,
	}
	if err := s.store.CreateOIDCIdentity(ctx, id); err != nil {
		return nil, err
	}
	return id, nil
}

// UpdateLastLogin updates the last login timestamp for an identity.
func (s *OIDCService) UpdateLastLogin(ctx context.Context, id int64) error {
	return s.store.UpdateOIDCLastLogin(ctx, id, time.Now())
}

// DeleteIdentity removes an OIDC identity link.
func (s *OIDCService) DeleteIdentity(ctx context.Context, id int64) error {
	return s.store.DeleteOIDCIdentity(ctx, id)
}

// CheckAdminClaim checks whether claims contain the expected admin value.
// Supports string, []any (list of strings), and bool claim types.
func CheckAdminClaim(adminClaim, adminValue string, claims map[string]any) bool {
	if adminClaim == "" || adminValue == "" {
		return false
	}

	claimValue, ok := claims[adminClaim]
	if !ok {
		return false
	}

	switch v := claimValue.(type) {
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok && str == adminValue {
				return true
			}
		}
	case string:
		return v == adminValue
	case bool:
		return v
	}

	return false
}
