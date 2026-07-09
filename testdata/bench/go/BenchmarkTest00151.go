package bench

import (
	"net/http"
)

// Hardcoded redirect
func Handler00151(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
