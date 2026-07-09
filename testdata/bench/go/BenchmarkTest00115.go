package bench

import (
	"fmt"
	"html"
	"net/http"
)

// html.EscapeString via channel
func Handler00115(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	ch := make(chan string, 1)
	ch <- html.EscapeString(input)
	safe := <-ch
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>%s</p>", safe)
}
