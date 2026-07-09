package bench

import (
	"net/http"
)

// Hardcoded redirect in goroutine
func Handler00156(w http.ResponseWriter, r *http.Request) {
	go func() {
		http.Redirect(w, r, "/login", http.StatusFound)
	}()
}
