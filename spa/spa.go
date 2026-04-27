// Package spa serves a compiled Vite/Svelte SPA from an embedded fs.FS.
//
// Static assets are served directly from the FS. All other paths return
// index.html with an optional config value injected as a JavaScript global
// before </head>.
package spa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

// Handler serves a compiled SPA. Construct with [New].
type Handler struct {
	distFS    fs.FS
	indexHTML []byte
}

// New creates a Handler that serves distFS.
//
// If config is non-nil, it is JSON-marshaled and injected into index.html as
// window[varName] before </head>. If varName is empty, "__APP_CONFIG__" is
// used.
func New(distFS fs.FS, varName string, config any) (*Handler, error) {
	raw, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		return nil, fmt.Errorf("spa: read index.html: %w", err)
	}

	if varName == "" {
		varName = "__APP_CONFIG__"
	}

	indexHTML := raw
	if config != nil {
		configJSON, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("spa: marshal config: %w", err)
		}
		script := "<script>window." + varName + "=" + string(configJSON) + "</script>"
		indexHTML = bytes.Replace(raw, []byte("</head>"), []byte(script+"</head>"), 1)
	}

	return &Handler{distFS: distFS, indexHTML: indexHTML}, nil
}

// ServeHTTP serves static assets from the embedded FS and falls back to
// index.html for all other paths (SPA client-side routing).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")

	if path != "" && path != "index.html" {
		if f, err := fs.Stat(h.distFS, path); err == nil && !f.IsDir() {
			http.ServeFileFS(w, r, h.distFS, path)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(h.indexHTML)
}
