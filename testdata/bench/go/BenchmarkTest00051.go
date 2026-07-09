package bench

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// filepath.Base sanitizer
func Handler00051(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	safe := filepath.Base(name)
	f, _ := os.Open(filepath.Join("/uploads", safe))
	defer f.Close()
	io.Copy(w, f)
}
