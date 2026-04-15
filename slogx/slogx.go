// Package slogx wraps log/slog with convenience helpers so callers only
// need a single import for structured logging.
//
// It re-exports the most commonly used slog types and functions, adds
// context-based logger passing, format configuration (JSON, pretty, text),
// and a small set of attribute helpers.
package slogx

import (
	"bytes"
	"context"
	"encoding"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

// Re-export slog levels so callers don't need to import both packages.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Re-export common slog attribute constructors.
var (
	String   = slog.String
	Int      = slog.Int
	Int64    = slog.Int64
	Bool     = slog.Bool
	Float64  = slog.Float64
	Duration = slog.Duration
	Time     = slog.Time
	Any      = slog.Any
	Group    = slog.Group
)

// Err creates an slog.Attr for an error value, keyed as "err".
func Err(err error) slog.Attr {
	return slog.Any("err", err)
}

// --- Format ---

// Format selects the log output format.
type Format int

const (
	FormatJSON Format = iota
	FormatPretty
	FormatText
)

var (
	_ encoding.TextUnmarshaler = (*Format)(nil)
	_ encoding.TextMarshaler   = Format(0)
)

func (f *Format) UnmarshalText(text []byte) error {
	switch string(bytes.ToLower(text)) {
	case "json":
		*f = FormatJSON
	case "pretty":
		*f = FormatPretty
	case "text":
		*f = FormatText
	default:
		return fmt.Errorf("unknown log format %q", text)
	}
	return nil
}

func (f Format) MarshalText() ([]byte, error) {
	switch f {
	case FormatJSON:
		return []byte("json"), nil
	case FormatPretty:
		return []byte("pretty"), nil
	case FormatText:
		return []byte("text"), nil
	default:
		return nil, fmt.Errorf("unknown log format %d", f)
	}
}

// --- Logger construction ---

// Config holds logger configuration.
type Config struct {
	Format Format
	Level  slog.Level
}

// New creates a logger from a Config. It also sets the slog default.
func New(cfg Config) *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     cfg.Level,
	}

	switch cfg.Format {
	case FormatPretty:
		handler = tint.NewHandler(os.Stdout, &tint.Options{
			AddSource:  true,
			Level:      cfg.Level,
			TimeFormat: time.Kitchen,
		})
	case FormatText:
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

// --- Context ---

type contextKey string

const loggerKey contextKey = "slogx_logger"

// FromContext retrieves a logger from the context. Returns slog.Default()
// if none is set.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// WithLogger attaches a logger to a context.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}
