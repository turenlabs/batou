package vulnerable

import (
	"fmt"
	"net/http"
)

// VULN: Reflected XSS - user input written directly to HTTP response without escaping.
// Should trigger taint analysis for go.fmt.fprintf.response sink with user input source.

func HandleProfile(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", name)
}

func HandleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><p>Search results for: %s</p></body></html>", query)
}
