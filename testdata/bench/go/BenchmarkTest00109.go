package bench

import (
	"fmt"
	"net/http"
)

// XSS via PostFormValue
func Handler00109(w http.ResponseWriter, r *http.Request) {
	comment := r.PostFormValue("comment")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<div class='comment'>%s</div>", comment)
}
