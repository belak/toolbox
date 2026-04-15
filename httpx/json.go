package httpx

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is a standard JSON error format.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// RespondJSON writes a JSON response with the given status code.
func RespondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// RespondError writes a JSON error response.
func RespondError(w http.ResponseWriter, status int, message, code string) {
	RespondJSON(w, status, ErrorResponse{Error: message, Code: code})
}

// DecodeJSON reads a JSON request body into dst. Returns false and writes
// a 400 error if decoding fails.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid request body", "bad_request")
		return false
	}
	return true
}
