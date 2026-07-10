package bench

import (
	"net/http"
)

// Open redirect via Location header
func Handler00149(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("dest")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}
