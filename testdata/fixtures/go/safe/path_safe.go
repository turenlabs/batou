package safe

import (
	"net/http"
	"path/filepath"
	"strings"
)

// SAFE: Path traversal prevention using filepath.Clean and strings.HasPrefix.
// Should NOT trigger GTSS-TRV-001.

const baseDir = "/var/www/static"

func HandleFileDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// Clean the path to resolve ".." sequences
	cleaned := filepath.Clean(filename)

	// Build full path
	fullPath := filepath.Join(baseDir, cleaned)

	// Resolve to absolute path
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Verify the resolved path stays within the base directory
	if !strings.HasPrefix(absPath, baseDir) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, absPath)
}
