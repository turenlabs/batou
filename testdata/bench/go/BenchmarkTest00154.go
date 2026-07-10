package bench

import (
	"net/http"
)

// Allowlist of paths
func Handler00154(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("dest")
	allowed := map[string]bool{"/home": true, "/profile": true, "/settings": true}
	if !allowed[dest] {
		dest = "/home"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
