package httpx

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/belak/toolbox/versionx"
)

const renderInfoKey contextKey = "render_info"

// RenderInfo carries metadata used by templates to display build and
// timing details (Go version, app version, request start time).
type RenderInfo struct {
	GoVersion  string
	AppVersion string
	StartTime  time.Time
}

// WithRenderInfo attaches a RenderInfo to the request context.
func WithRenderInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := &RenderInfo{
			GoVersion:  runtime.Version(),
			AppVersion: versionx.Get(),
			StartTime:  time.Now(),
		}
		ctx := context.WithValue(r.Context(), renderInfoKey, info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRenderInfo returns the RenderInfo from ctx, or nil if the
// middleware was not installed.
func GetRenderInfo(ctx context.Context) *RenderInfo {
	info, _ := ctx.Value(renderInfoKey).(*RenderInfo)
	return info
}

// GetRenderTime returns the elapsed time since the request started, as
// a rounded duration string. Returns "" if WithRenderInfo was not
// installed.
func GetRenderTime(ctx context.Context) string {
	info := GetRenderInfo(ctx)
	if info == nil {
		return ""
	}
	d := time.Since(info.StartTime)
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
