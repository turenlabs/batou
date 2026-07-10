package bench

import (
	"fmt"
	"net/http"
)

// XSS via fmt.Fprintf
func Handler00101(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
