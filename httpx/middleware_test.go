package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/belak/toolbox/httpx"
)

func tagMiddleware(tag string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Tag", tag)
			next.ServeHTTP(w, r)
		})
	}
}

func TestByMethodReadVsWrite(t *testing.T) {
	t.Parallel()

	mw := httpx.ByMethod(tagMiddleware("read"), tagMiddleware("write"))
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		method string
		want   string
	}{
		{http.MethodGet, "read"},
		{http.MethodHead, "read"},
		{http.MethodOptions, "read"},
		{http.MethodPost, "write"},
		{http.MethodPut, "write"},
		{http.MethodPatch, "write"},
		{http.MethodDelete, "write"},
		{"BREW", "write"}, // unknown methods default to write
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tc.want, w.Header().Get("X-Tag"))
		})
	}
}

func TestByMethodExtraReadMethods(t *testing.T) {
	t.Parallel()
	mw := httpx.ByMethod(tagMiddleware("read"), tagMiddleware("write"), "PROPFIND")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("PROPFIND", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, "read", w.Header().Get("X-Tag"))
}

func TestByMethodNilReadOrWrite(t *testing.T) {
	t.Parallel()

	// nil read => GET passes through unwrapped; POST goes through write.
	mw := httpx.ByMethod(nil, tagMiddleware("write"))
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, "", w.Header().Get("X-Tag"))

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, "write", w.Header().Get("X-Tag"))
}

func TestCSPSetsHeader(t *testing.T) {
	t.Parallel()
	policy := "default-src 'self'"
	handler := httpx.CSP(policy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, policy, w.Header().Get("Content-Security-Policy"))
}
