package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/belak/toolbox/slogx"
	"github.com/felixge/httpsnoop"
)

// Middleware is the standard middleware signature.
type Middleware func(http.Handler) http.Handler

type contextKey string

const requestIDKey contextKey = "request_id"

var requestIDHeader = "X-Request-ID"

// GetRequestID retrieves the request ID from the context, or empty string.
func GetRequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// RequestID adds a unique request ID to each request. If the request
// already has an X-Request-ID header (e.g. from a load balancer), it is
// reused.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = generateRequestID()
		}

		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "req_error"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Logging creates middleware that logs each request with method, path,
// status, duration, and bytes written. It attaches a child logger with
// the request ID to the context.
func Logging(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := GetRequestID(r.Context())

			// Child logger with request ID for downstream handlers.
			reqLogger := logger.With(slogx.String("request_id", requestID))
			ctx := slogx.WithLogger(r.Context(), reqLogger)
			r = r.WithContext(ctx)

			m := httpsnoop.CaptureMetrics(next, w, r)

			reqLogger.Info("http request",
				slogx.Group("http",
					slogx.String("method", r.Method),
					slogx.String("path", r.URL.Path),
					slogx.Int("status", m.Code),
					slogx.Duration("duration", m.Duration),
					slogx.Int64("bytes", m.Written),
				),
			)
		})
	}
}

// Recovery creates middleware that recovers from panics, logs the error
// and stack trace, and returns 500.
func Recovery(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						slogx.Any("error", err),
						slogx.String("method", r.Method),
						slogx.String("path", r.URL.Path),
						slogx.String("stack", string(debug.Stack())),
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds standard security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}
