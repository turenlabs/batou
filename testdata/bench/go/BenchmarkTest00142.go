package bench

import (
	"net/http"
)

// Open redirect via FormValue
func Handler00142(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	http.Redirect(w, r, next, http.StatusMovedPermanently)
}
