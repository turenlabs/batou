package bench

import (
	"net/http"
)

// Open redirect via string concat
func Handler00148(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	target := "http://" + path
	http.Redirect(w, r, target, http.StatusFound)
}
