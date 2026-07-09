package bench

import (
	"fmt"
	"html"
	"net/http"
)

// html.EscapeString sanitizer
func Handler00111(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	safe := html.EscapeString(name)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", safe)
}
