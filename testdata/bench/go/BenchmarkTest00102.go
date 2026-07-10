package bench

import (
	"net/http"
)

// XSS via w.Write
func Handler00102(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<div>" + msg + "</div>"))
}
