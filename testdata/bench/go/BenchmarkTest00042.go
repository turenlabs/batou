package bench

import (
	"net/http"
	"os"
)

// Path traversal via os.ReadFile
func Handler00042(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	data, _ := os.ReadFile(path)
	w.Write(data)
}
