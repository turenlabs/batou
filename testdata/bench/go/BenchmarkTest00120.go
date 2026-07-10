package bench

import (
	"fmt"
	"net/http"
	"net/url"
)

// url.QueryEscape for attribute
func Handler00120(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	safe := url.QueryEscape(q)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<a href='/search?q=%s'>Search</a>", safe)
}
