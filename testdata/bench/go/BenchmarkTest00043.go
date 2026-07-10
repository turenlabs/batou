package bench

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Path traversal via filepath.Join unsanitized
func Handler00043(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	full := filepath.Join("/data/uploads", name)
	f, _ := os.Open(full)
	defer f.Close()
	io.Copy(w, f)
}
