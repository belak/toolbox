package auth

import (
	"fmt"
	"net/http"
)

// DefaultPKCECookieName is used when [PKCECookie.CookieName] is empty.
const DefaultPKCECookieName = "oidc_pkce"

// PKCECookie persists an OIDC PKCE verifier across the authorization
// redirect. The verifier must survive from the AuthCodeURL call until the
// callback handler calls Exchange.
//
// This is the recommended default for server-rendered apps and for SPAs
// that lack a pre-auth session store. Callers using session storage or
// another persistence layer can skip this type.
type PKCECookie struct {
	// CookieName overrides the cookie name. Empty uses DefaultPKCECookieName.
	CookieName string
}

func (p *PKCECookie) cookieName() string {
	if p.CookieName == "" {
		return DefaultPKCECookieName
	}
	return p.CookieName
}

// Set stores the PKCE verifier in a short-lived cookie. MaxAge matches
// [StateExpiry] so the verifier and state age out together.
func (p *PKCECookie) Set(w http.ResponseWriter, verifier string) {
	http.SetCookie(w, &http.Cookie{
		Name:     p.cookieName(),
		Value:    verifier,
		Path:     "/",
		MaxAge:   int(StateExpiry.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Get retrieves and clears the PKCE verifier. Returns an error if no
// cookie is set. The cookie is cleared on every call — verifiers are
// single-use.
func (p *PKCECookie) Get(w http.ResponseWriter, r *http.Request) (string, error) {
	name := p.cookieName()
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", fmt.Errorf("reading pkce cookie: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	return cookie.Value, nil
}
