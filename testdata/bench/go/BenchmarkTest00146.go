package bench

import (
	"net/http"
)

// Open redirect via PostFormValue
func Handler00146(w http.ResponseWriter, r *http.Request) {
	target := r.PostFormValue("return_url")
	http.Redirect(w, r, target, http.StatusFound)
}
