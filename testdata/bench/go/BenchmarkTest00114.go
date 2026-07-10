package bench

import (
	"fmt"
	"net/http"
)

// Plaintext content type
func Handler00114(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, msg)
}
