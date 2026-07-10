package bench

import (
	"fmt"
	"net/http"
)

// XSS via channel propagation
func Handler00104(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	ch := make(chan string, 1)
	ch <- input
	val := <-ch
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Search: %s</p>", val)
}
