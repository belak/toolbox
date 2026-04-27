package auth

import (
	"context"
	"net/http"
)

// Kind identifies how a request was authenticated. The built-in
// resolvers stamp the kind onto the request context so handlers and
// middleware can gate on auth method (e.g. "session-only" endpoints).
type Kind string

// Built-in auth kinds. Custom resolvers may use additional values; the
// kind is just an opaque tag.
const (
	KindSession Kind = "session"
	KindBearer  Kind = "bearer"
	KindBasic   Kind = "basic"
)

type kindKeyT struct{}

var kindKey kindKeyT

// WithKind returns a new context tagged with the given auth kind.
func WithKind(ctx context.Context, k Kind) context.Context {
	return context.WithValue(ctx, kindKey, k)
}

// GetKind returns the auth kind stamped on ctx, or "" and ok=false if
// no kind was attached (typically because the request is
// unauthenticated or used a custom resolver that did not stamp one).
func GetKind(ctx context.Context) (Kind, bool) {
	k, ok := ctx.Value(kindKey).(Kind)
	return k, ok
}

// RequireKind returns middleware that allows the request through only
// when GetKind matches one of allowed. Requests without a kind, or with
// a non-matching kind, invoke onFail (defaults to 403 Forbidden).
//
// Compose after AuthMiddleware.Require: that middleware enforces "must
// be authenticated"; RequireKind enforces "must be authenticated this
// way".
func RequireKind(onFail http.HandlerFunc, allowed ...Kind) func(http.Handler) http.Handler {
	if onFail == nil {
		onFail = func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
	}
	set := make(map[Kind]struct{}, len(allowed))
	for _, k := range allowed {
		set[k] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			k, ok := GetKind(r.Context())
			if !ok {
				onFail(w, r)
				return
			}
			if _, allowed := set[k]; !allowed {
				onFail(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
