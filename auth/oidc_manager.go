package auth

import (
	"fmt"
	"log/slog"
)

// OIDCManager manages multiple OIDC providers.
type OIDCManager struct {
	providers map[string]*OIDCService
	logger    *slog.Logger
}

// OIDCManagerOption configures an OIDCManager.
type OIDCManagerOption func(*OIDCManager)

// WithOIDCManagerLogger sets the logger for the manager.
func WithOIDCManagerLogger(l *slog.Logger) OIDCManagerOption {
	return func(m *OIDCManager) { m.logger = l }
}

// NewOIDCManager creates an OIDCManager. Providers are added with Register.
func NewOIDCManager(opts ...OIDCManagerOption) *OIDCManager {
	m := &OIDCManager{
		providers: make(map[string]*OIDCService),
		logger:    slog.Default(),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Register adds a named OIDC provider. The name is used in state parameters
// and URL routing (e.g. "google", "okta", "github").
func (m *OIDCManager) Register(name string, cfg OIDCConfig, secret []byte, store OIDCIdentityStore) {
	svc := NewOIDCService(cfg, secret, store, WithOIDCLogger(m.logger))
	m.providers[name] = svc
}

// Provider returns the OIDCService for the given name, or an error if not
// registered.
func (m *OIDCManager) Provider(name string) (*OIDCService, error) {
	svc, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown OIDC provider: %q", name)
	}
	return svc, nil
}

// Providers returns all registered provider names.
func (m *OIDCManager) Providers() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// Len returns the number of registered providers.
func (m *OIDCManager) Len() int {
	return len(m.providers)
}
