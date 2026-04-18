package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
)

type ctxKey struct{ name string }

var flashKey = ctxKey{"flash"}

func TestFlashSetAndGet(t *testing.T) {
	f := &Flash{}

	setRec := httptest.NewRecorder()
	f.Set(setRec, "success", "saved")

	cookies := setRec.Result().Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, DefaultFlashCookieName, cookies[0].Name)

	getRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])

	msg := f.Get(getRec, req)
	assert.NotEqual(t, nil, msg)
	assert.Equal(t, "success", msg.Type)
	assert.Equal(t, "saved", msg.Message)

	// Get should emit a clearing cookie.
	cleared := getRec.Result().Cookies()
	assert.Equal(t, 1, len(cleared))
	assert.Equal(t, DefaultFlashCookieName, cleared[0].Name)
	assert.Equal(t, -1, cleared[0].MaxAge)
}

func TestFlashCustomCookieName(t *testing.T) {
	f := &Flash{CookieName: "myapp_flash"}

	w := httptest.NewRecorder()
	f.Set(w, "info", "hi")

	cookies := w.Result().Cookies()
	assert.Equal(t, "myapp_flash", cookies[0].Name)
}

func TestFlashGetNoCookie(t *testing.T) {
	f := &Flash{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, (*FlashMessage)(nil), f.Get(httptest.NewRecorder(), req))
}

func TestFlashMiddleware(t *testing.T) {
	f := &Flash{}

	// Prime a cookie as if set by a previous request.
	primer := httptest.NewRecorder()
	f.Set(primer, "warning", "heads up")
	primed := primer.Result().Cookies()[0]

	var gotMsg *FlashMessage
	handler := f.Middleware(flashKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMsg, _ = r.Context().Value(flashKey).(*FlashMessage)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(primed)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, nil, gotMsg)
	assert.Equal(t, "warning", gotMsg.Type)
	assert.Equal(t, "heads up", gotMsg.Message)
}

func TestFlashMiddlewareNoCookie(t *testing.T) {
	f := &Flash{}

	var sawMsg bool
	handler := f.Middleware(flashKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawMsg = r.Context().Value(flashKey).(*FlashMessage)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, sawMsg)
}
