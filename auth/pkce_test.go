package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestPKCECookieSetAndGet(t *testing.T) {
	p := &PKCECookie{}

	setRec := httptest.NewRecorder()
	p.Set(setRec, "verifier-abc")

	cookies := setRec.Result().Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, DefaultPKCECookieName, cookies[0].Name)
	assert.Equal(t, "verifier-abc", cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)

	getRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])

	verifier, err := p.Get(getRec, req)
	assert.NoError(t, err)
	assert.Equal(t, "verifier-abc", verifier)

	cleared := getRec.Result().Cookies()
	assert.Equal(t, 1, len(cleared))
	assert.Equal(t, -1, cleared[0].MaxAge)
}

func TestPKCECookieCustomName(t *testing.T) {
	p := &PKCECookie{CookieName: "myapp_pkce"}

	w := httptest.NewRecorder()
	p.Set(w, "v")

	assert.Equal(t, "myapp_pkce", w.Result().Cookies()[0].Name)
}

func TestPKCECookieGetMissing(t *testing.T) {
	p := &PKCECookie{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := p.Get(httptest.NewRecorder(), req)
	assert.Error(t, err)
}
