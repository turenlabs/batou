package bench

import (
	"fmt"
	"net/http"
)

// XSS via goroutine write
func Handler00105(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	w.Header().Set("Content-Type", "text/html")
	go func() {
		fmt.Fprintf(w, "<span>%s</span>", msg)
	}()
}
