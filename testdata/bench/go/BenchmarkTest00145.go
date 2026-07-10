package bench

import (
	"net/http"
)

// Open redirect via variable hop
func Handler00145(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("goto")
	dest := raw
	http.Redirect(w, r, dest, http.StatusFound)
}
