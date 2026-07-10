package bench

import (
	"net/http"
	"os"
	"path/filepath"
)

// Allowlist of filenames
func Handler00057(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("doc")
	allowed := map[string]bool{"readme.txt": true, "license.txt": true}
	if !allowed[name] {
		http.Error(w, "not found", 404)
		return
	}
	data, _ := os.ReadFile(filepath.Join("/docs", name))
	w.Write(data)
}
