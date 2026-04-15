package httpx

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// FlashMessage represents a one-time feedback message displayed after a
// redirect (e.g. "File uploaded successfully").
type FlashMessage struct {
	Type    string `json:"type"` // "success", "error", "warning", "info"
	Message string `json:"message"`
}

// SetFlash stores a flash message in a cookie. The message is consumed on
// the next request by GetFlash.
func SetFlash(w http.ResponseWriter, cookieName, flashType, message string) {
	data, err := json.Marshal(FlashMessage{Type: flashType, Message: message})
	if err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    base64.StdEncoding.EncodeToString(data),
		Path:     "/",
		MaxAge:   60, // 1 minute, enough for a redirect
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetFlash retrieves and clears the flash message cookie. Returns nil if
// no flash is set.
func GetFlash(w http.ResponseWriter, r *http.Request, cookieName string) *FlashMessage {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}

	// Clear immediately. Flash messages are single-use.
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
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
