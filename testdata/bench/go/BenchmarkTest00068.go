package bench

import (
	"net/http"
)

// SSRF via defer
func Handler00068(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("notify")
	defer http.Get(target)
	w.WriteHeader(200)
}
