package bench

import (
	"fmt"
	"net/http"
)

// XSS via Header reflection
func Handler00106(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Your browser: %s</p>", ua)
}
