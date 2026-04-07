package vulnerable

import (
	"net/http"
	"path/filepath"
)

// VULN: Path traversal via unsanitized user-controlled path passed to http.ServeFile.
// Should trigger BATOU-TRV-001 (Path Traversal).

const staticDir = "/var/www/static"

func HandleFileDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	fullPath := filepath.Join(staticDir, filename)
	http.ServeFile(w, r, fullPath)
}
