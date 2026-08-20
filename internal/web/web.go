// Package web serves the built frontend from inside the binary.
//
// Embedding it means there is no separate web root to deploy and no way for
// the frontend and backend to drift apart in a deployment: whatever the
// binary serves is exactly what was built alongside it.
package web

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// dist holds the built frontend. The all: prefix includes files whose names
// begin with an underscore, which some bundlers emit.
//
//go:embed all:dist
var dist embed.FS

// ErrNotBuilt means the binary was compiled without a built frontend.
//
// Reported rather than silently serving nothing, because the symptom
// otherwise is a blank page with a 404 in the console — a confusing way to
// discover that `make web` was skipped.
var ErrNotBuilt = errors.New("web: the frontend has not been built; run 'make web' before 'make build'")

// FS returns the built assets.
func FS() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, err
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, ErrNotBuilt
	}
	return sub, nil
}

// Available reports whether a built frontend is present.
func Available() bool {
	_, err := FS()
	return err == nil
}

// Handler serves the frontend as a single-page application.
//
// Any path that is not a real file returns index.html, so a browser reload on
// a client-side route works instead of 404ing. Requests under /api are never
// routed here — the caller mounts this only as a fallback.
func Handler() (http.Handler, error) {
	assets, err := FS()
	if err != nil {
		return nil, err
	}

	fileServer := http.FileServer(http.FS(assets))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." || clean == "/" {
			clean = "index.html"
		}

		info, statErr := fs.Stat(assets, clean)
		if statErr != nil || info.IsDir() {
			// A client-side route. Serve the shell and let the app resolve it.
			//
			// no-store rather than a long cache: index.html references the
			// hashed asset filenames, so a cached copy after an upgrade would
			// point at files that no longer exist.
			w.Header().Set("Cache-Control", "no-store")
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}

		// Hashed asset names change on every build, so they are safe to cache
		// indefinitely; an upgrade takes effect because index.html points at
		// new names.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}
