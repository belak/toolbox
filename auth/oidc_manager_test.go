package auth

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestOIDCManagerRegisterAndLookup(t *testing.T) {
	mgr := NewOIDCManager()

	mgr.Register("google", OIDCConfig{
		IssuerURL: "https://accounts.google.com",
		ClientID:  "google-id",
	}, []byte("secret"), nil)

	mgr.Register("okta", OIDCConfig{
		IssuerURL: "https://dev-123.okta.com",
		ClientID:  "okta-id",
	}, []byte("secret"), nil)

	assert.Equal(t, 2, mgr.Len())

	google, err := mgr.Provider("google")
	assert.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", google.IssuerURL())

	okta, err := mgr.Provider("okta")
	assert.NoError(t, err)
	assert.Equal(t, "https://dev-123.okta.com", okta.IssuerURL())
}

func TestOIDCManagerUnknownProvider(t *testing.T) {
	mgr := NewOIDCManager()

	_, err := mgr.Provider("nope")
	assert.Error(t, err)
}

func TestOIDCManagerProviderNames(t *testing.T) {
	mgr := NewOIDCManager()
	mgr.Register("a", OIDCConfig{IssuerURL: "https://a.example.com"}, []byte("s"), nil)
	mgr.Register("b", OIDCConfig{IssuerURL: "https://b.example.com"}, []byte("s"), nil)

	names := mgr.Providers()
	assert.Equal(t, 2, len(names))
}

func TestOIDCManagerEachProviderHasOwnState(t *testing.T) {
	mgr := NewOIDCManager()

	mgr.Register("a", OIDCConfig{IssuerURL: "https://a.example.com"}, []byte("secret-a"), nil)
	mgr.Register("b", OIDCConfig{IssuerURL: "https://b.example.com"}, []byte("secret-b"), nil)

	a, _ := mgr.Provider("a")
	b, _ := mgr.Provider("b")

	// State from provider A should not verify against provider B.
	state, err := a.GenerateState("login")
	assert.NoError(t, err)

	_, err = b.VerifyState(state)
	assert.Error(t, err)

	// But should verify against itself.
	flow, err := a.VerifyState(state)
	assert.NoError(t, err)
	assert.Equal(t, "login", flow)
}
