package bench

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// filepath.Clean + HasPrefix check
func Handler00052(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("path")
	cleaned := filepath.Clean(filepath.Join("/data", name))
	if !strings.HasPrefix(cleaned, "/data/") {
		http.Error(w, "forbidden", 403)
		return
	}
	data, _ := os.ReadFile(cleaned)
	w.Write(data)
}
