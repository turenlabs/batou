package bench

import (
	"net/http"
)

// Open redirect via Header
func Handler00143(w http.ResponseWriter, r *http.Request) {
	location := r.Header.Get("X-Redirect")
	http.Redirect(w, r, location, http.StatusFound)
}
