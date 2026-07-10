package bench

import (
	"fmt"
	"net/http"
)

// XSS via fmt.Fprint
func Handler00107(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<title>"+title+"</title>")
}
