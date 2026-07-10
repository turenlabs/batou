package bench

import (
	"net/http"
)

// Hardcoded via channel
func Handler00155(w http.ResponseWriter, r *http.Request) {
	ch := make(chan string, 1)
	ch <- "/home"
	dest := <-ch
	http.Redirect(w, r, dest, http.StatusFound)
}
