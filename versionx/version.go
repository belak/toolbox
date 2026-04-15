// Package versionx extracts version information from Go build info.
package versionx

import (
	"runtime"
	"runtime/debug"
	"sync"
)

var (
	cached string
	once   sync.Once
)

// Get returns the application version. If any non-empty override is
// provided, the first one is returned (useful for ldflags stamping).
// Otherwise it extracts the VCS revision from build info, falling back
// to "unknown".
func Get(overrides ...string) string {
	for _, o := range overrides {
		if o != "" {
			return o
		}
	}

	once.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			cached = "unknown"
			return
		}

		var rev, dirty string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}

		if rev != "" {
			cached = rev + dirty
			return
		}

		if info.Main.Version == "(devel)" {
			cached = "dev"
			return
		}

		cached = "unknown"
	})

	return cached
}

// GoVersion returns the Go runtime version.
func GoVersion() string {
	return runtime.Version()
}
