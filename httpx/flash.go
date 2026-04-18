package httpx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// DefaultFlashCookieName is used when [Flash.CookieName] is empty.
const DefaultFlashCookieName = "flash"

// FlashMessage represents a one-time feedback message displayed after a
// redirect (e.g. "File uploaded successfully").
type FlashMessage struct {
	Type    string `json:"type"` // "success", "error", "warning", "info"
	Message string `json:"message"`
}

// Flash reads and writes one-shot feedback messages via cookie.
type Flash struct {
	// CookieName overrides the cookie name. Empty uses DefaultFlashCookieName.
	CookieName string
}

func (f *Flash) cookieName() string {
	if f.CookieName == "" {
		return DefaultFlashCookieName
	}
	return f.CookieName
}

// Set stores a flash message. The message is consumed on the next request
// by Get.
func (f *Flash) Set(w http.ResponseWriter, kind, message string) {
	data, err := json.Marshal(FlashMessage{Type: kind, Message: message})
	if err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     f.cookieName(),
		Value:    base64.StdEncoding.EncodeToString(data),
		Path:     "/",
		MaxAge:   60, // 1 minute, enough for a redirect
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Get retrieves and clears the flash cookie. Returns nil if no flash is set.
func (f *Flash) Get(w http.ResponseWriter, r *http.Request) *FlashMessage {
	name := f.cookieName()
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil
	}

	// Clear immediately. Flash messages are single-use.
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}

	var flash FlashMessage
	if err := json.Unmarshal(decoded, &flash); err != nil {
		return nil
	}
	return &flash
}

// Middleware loads any flash message into the request context under key,
// clearing the cookie. Handlers retrieve it via a caller-owned helper.
func (f *Flash) Middleware(key any) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if msg := f.Get(w, r); msg != nil {
				r = r.WithContext(context.WithValue(r.Context(), key, msg))
			}
			next.ServeHTTP(w, r)
		})
	}
}
