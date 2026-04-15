package auth

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestOIDCStateRoundtrip(t *testing.T) {
	// We can't easily test full OIDC flow without a provider, but we can
	// test state generation/verification which is self-contained.
	secret := []byte("test-secret-key-for-hmac-signing")

	svc := &OIDCService{secret: secret}

	state, err := svc.GenerateState("login")
	assert.NoError(t, err)
	assert.NotEqual(t, "", state)

	flow, err := svc.VerifyState(state)
	assert.NoError(t, err)
	assert.Equal(t, "login", flow)
}

func TestOIDCStateWrongSecret(t *testing.T) {
	svc1 := &OIDCService{secret: []byte("secret-1")}
	svc2 := &OIDCService{secret: []byte("secret-2")}

	state, err := svc1.GenerateState("link")
	assert.NoError(t, err)

	_, err = svc2.VerifyState(state)
	assert.Error(t, err)
}

func TestOIDCStateTampered(t *testing.T) {
	svc := &OIDCService{secret: []byte("secret")}

	state, _ := svc.GenerateState("login")
	// Flip a character.
	tampered := state[:len(state)-1] + "X"

	_, err := svc.VerifyState(tampered)
	assert.Error(t, err)
}

func TestOIDCNotReadyBeforeDiscovery(t *testing.T) {
	svc := NewOIDCService(
		OIDCConfig{IssuerURL: "https://not-a-real-provider.example.com"},
		[]byte("secret"),
		nil,
	)
	assert.False(t, svc.Ready())
}

func TestOIDCLazyInitFailsGracefully(t *testing.T) {
	svc := NewOIDCService(
		OIDCConfig{IssuerURL: "https://not-a-real-provider.example.com"},
		[]byte("secret"),
		nil,
	)

	// AuthCodeURL should fail because discovery will fail.
	_, _, err := svc.AuthCodeURL(t.Context(), "state")
	assert.Error(t, err)
	assert.False(t, svc.Ready()) // still not ready after failure

	// State gen/verify still work without discovery.
	state, err := svc.GenerateState("login")
	assert.NoError(t, err)
	flow, err := svc.VerifyState(state)
	assert.NoError(t, err)
	assert.Equal(t, "login", flow)
}

func TestCheckAdminClaim(t *testing.T) {
	tests := []struct {
		name       string
		adminClaim string
		adminValue string
		claims     map[string]any
		want       bool
	}{
		{
			name:       "string match",
			adminClaim: "role",
			adminValue: "admin",
			claims:     map[string]any{"role": "admin"},
			want:       true,
		},
		{
			name:       "string no match",
			adminClaim: "role",
			adminValue: "admin",
			claims:     map[string]any{"role": "user"},
			want:       false,
		},
		{
			name:       "list contains value",
			adminClaim: "groups",
			adminValue: "admins",
			claims:     map[string]any{"groups": []any{"users", "admins"}},
			want:       true,
		},
		{
			name:       "list missing value",
			adminClaim: "groups",
			adminValue: "admins",
			claims:     map[string]any{"groups": []any{"users"}},
			want:       false,
		},
		{
			name:       "bool true",
			adminClaim: "is_admin",
			adminValue: "true",
			claims:     map[string]any{"is_admin": true},
			want:       true,
		},
		{
			name:       "bool false",
			adminClaim: "is_admin",
			adminValue: "true",
			claims:     map[string]any{"is_admin": false},
			want:       false,
		},
		{
			name:       "missing claim",
			adminClaim: "role",
			adminValue: "admin",
			claims:     map[string]any{},
			want:       false,
		},
		{
			name:       "empty config",
			adminClaim: "",
			adminValue: "",
			claims:     map[string]any{"role": "admin"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckAdminClaim(tt.adminClaim, tt.adminValue, tt.claims)
			assert.Equal(t, tt.want, got)
		})
	}
}
