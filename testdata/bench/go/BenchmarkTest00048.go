package bench

import (
	"net/http"
	"os"
)

// Path traversal via Header
func Handler00048(w http.ResponseWriter, r *http.Request) {
	path := r.Header.Get("X-File-Path")
	data, _ := os.ReadFile(path)
	w.Write(data)
}
