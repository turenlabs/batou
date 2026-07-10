package bench

import (
	"net/http"
)

// Hardcoded with defer
func Handler00159(w http.ResponseWriter, r *http.Request) {
	_ = r.FormValue("ignored")
	defer http.Redirect(w, r, "/done", http.StatusFound)
}
