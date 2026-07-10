package bench

import (
	"fmt"
	"net/http"
)

// XSS via defer write
func Handler00108(w http.ResponseWriter, r *http.Request) {
	footer := r.FormValue("footer")
	w.Header().Set("Content-Type", "text/html")
	defer fmt.Fprintf(w, "<footer>%s</footer>", footer)
}
