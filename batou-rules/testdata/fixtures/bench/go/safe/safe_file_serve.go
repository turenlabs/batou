package safe

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const uploadDir = "/var/www/uploads"

// SAFE: filepath.Clean + strings.HasPrefix for path traversal prevention
func ServeUpload(w http.ResponseWriter, r *http.Request) {
	requested := r.URL.Query().Get("file")
	cleaned := filepath.Clean(filepath.Join(uploadDir, requested))

	if !strings.HasPrefix(cleaned, uploadDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if _, err := os.Stat(cleaned); os.IsNotExist(err) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	http.ServeFile(w, r, cleaned)
}

// SAFE: filepath.Base strips directory components
func ServeDocument(w http.ResponseWriter, r *http.Request) {
	rawName := r.URL.Query().Get("name")
	safeName := filepath.Base(rawName)
	fullPath := filepath.Join(uploadDir, safeName)

	http.ServeFile(w, r, fullPath)
}

// SAFE: Allowlist of permitted file names
func ServeStaticAsset(w http.ResponseWriter, r *http.Request) {
	allowed := map[string]bool{
		"logo.png":    true,
		"favicon.ico": true,
		"robots.txt":  true,
		"style.css":   true,
	}

	name := r.URL.Query().Get("asset")
	if !allowed[name] {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	http.ServeFile(w, r, filepath.Join("/var/www/static", name))
}
