package bench

import (
	"io"
	"net/http"
	"os"
)

// Path traversal via goroutine file write
func Handler00046(w http.ResponseWriter, r *http.Request) {
	dest := r.FormValue("output")
	body, _ := io.ReadAll(r.Body)
	go func() {
		os.WriteFile(dest, body, 0644)
	}()
}
