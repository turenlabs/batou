package bench

import (
	"net/http"
)

// Open redirect via goroutine-set header
func Handler00150(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	go func() {
		http.Redirect(w, r, target, http.StatusFound)
	}()
}
