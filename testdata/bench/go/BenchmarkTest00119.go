package bench

import (
	"fmt"
	"html"
	"net/http"
)

// html.EscapeString with defer
func Handler00119(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	safe := html.EscapeString(msg)
	w.Header().Set("Content-Type", "text/html")
	defer fmt.Fprintf(w, "<footer>%s</footer>", safe)
}
