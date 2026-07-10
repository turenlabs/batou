package bench

import (
	"net/http"
)

// Open redirect via http.Redirect
func Handler00141(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusFound)
}
