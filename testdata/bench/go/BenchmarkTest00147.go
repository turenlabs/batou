package bench

import (
	"net/http"
)

// Open redirect via Cookie
func Handler00147(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("redirect_to")
	http.Redirect(w, r, cookie.Value, http.StatusFound)
}
