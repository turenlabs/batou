package bench

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// filepath.Abs validation
func Handler00060(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	abs, _ := filepath.Abs(filepath.Join("/safe", name))
	if !strings.HasPrefix(abs, "/safe/") {
		http.Error(w, "forbidden", 403)
		return
	}
	data, _ := os.ReadFile(abs)
	w.Write(data)
}
