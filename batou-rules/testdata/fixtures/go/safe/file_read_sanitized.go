package safe

import (
	"net/http"
	"path/filepath"
	"strings"
)

// SAFE: Path traversal prevented by filepath.Base sanitization.
// Should NOT trigger SnkFileRead taint flow.

const staticDir = "/var/www/static"

func HandleStaticFileSafe(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	safe := filepath.Base(filename)
	fullPath := filepath.Join(staticDir, safe)
	http.ServeFile(w, r, fullPath)
}

// SAFE: Path traversal prevented by prefix check after Clean.

func HandleStaticFileWithPrefixCheck(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	clean := filepath.Clean(filepath.Join(staticDir, filename))
	if !strings.HasPrefix(clean, staticDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.ServeFile(w, r, clean)
}
