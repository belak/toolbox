package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/belak/toolbox/slogx"
)

const (
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
)

// Router wraps http.ServeMux with middleware support and route grouping.
type Router struct {
	logger      *slog.Logger
	middlewares []Middleware
	inner       *http.ServeMux
}

// NewRouter creates a Router with optional middleware already applied.
func NewRouter(logger *slog.Logger) *Router {
	return &Router{
		logger:      logger,
		inner:       http.NewServeMux(),
		middlewares: nil,
	}
}

// Use appends middleware to the stack. Middleware added here applies to
// all routes registered after this call (and within this group).
func (r *Router) Use(middlewares ...Middleware) {
	r.middlewares = append(r.middlewares, middlewares...)
}

// Group creates a sub-router that inherits the current middleware stack.
// Additional middleware or routes added inside the callback do not affect
// the parent.
func (r *Router) Group(fn func(*Router)) {
	child := &Router{
		logger:      r.logger,
		middlewares: slices.Clone(r.middlewares),
		inner:       r.inner,
	}
	fn(child)
}

// Handle registers a handler for the given pattern with all active
// middleware applied.
func (r *Router) Handle(pattern string, handler http.HandlerFunc) {
	var h http.Handler = handler
	for _, mw := range slices.Backward(r.middlewares) {
		h = mw(h)
	}
	r.inner.Handle(pattern, h)
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.inner.ServeHTTP(w, req)
}

// ListenAndServe starts the HTTP server. It supports both TCP ("host:port")
// and Unix socket ("unix:/path/to/socket") bind addresses. The server
// shuts down gracefully when ctx is cancelled.
func (r *Router) ListenAndServe(ctx context.Context, bind string) error {
	var listener net.Listener
	var cleanup func() error
	var err error

	if strings.HasPrefix(bind, "unix:") {
		path := strings.TrimPrefix(bind, "unix:")
		r.logger.Info("starting http listener", slogx.String("socket", path))

		_ = os.Remove(path) // remove stale socket
		listener, err = net.Listen("unix", path)
		if err != nil {
			return fmt.Errorf("creating unix socket: %w", err)
		}

		// #nosec G302 -- 0660 allows group access for reverse proxies
		if err := os.Chmod(path, 0660); err != nil {
			_ = listener.Close()
			return fmt.Errorf("setting socket permissions: %w", err)
		}
		cleanup = func() error { return os.Remove(path) }
	} else {
		r.logger.Info("starting http listener", slogx.String("bind", bind))
		listener, err = net.Listen("tcp", bind)
		if err != nil {
			return fmt.Errorf("creating tcp listener: %w", err)
		}
		cleanup = func() error { return nil }
	}

	server := &http.Server{
		Handler:           r,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
	}

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		r.logger.Info("shutting down server")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		r.logger.Error("graceful shutdown failed", slogx.Err(err))
		_ = listener.Close()
		_ = cleanup()
		return err
	}

	if err := cleanup(); err != nil {
		r.logger.Error("cleanup failed", slogx.Err(err))
	}

	r.logger.Info("server stopped")
	return nil
}

// WithSignalShutdown returns a context that is cancelled on SIGINT or
// SIGTERM.
func WithSignalShutdown(ctx context.Context, logger *slog.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s := <-sig
		logger.Info("shutdown signal received", slogx.String("signal", s.String()))
		cancel()
	}()

	return ctx, cancel
}
