package bench

import (
	"net/http"
	"os"
	"path/filepath"
)

// filepath.Base in goroutine
func Handler00056(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	safe := filepath.Base(name)
	go func() {
		data, _ := os.ReadFile(filepath.Join("/safe", safe))
		_ = data
	}()
}
