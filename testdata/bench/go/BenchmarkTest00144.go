package bench

import (
	"net/http"
)

// Open redirect via channel
func Handler00144(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("redirect")
	ch := make(chan string, 1)
	ch <- target
	dest := <-ch
	http.Redirect(w, r, dest, http.StatusTemporaryRedirect)
}
