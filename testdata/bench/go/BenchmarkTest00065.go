package bench

import (
	"net/http"
)

// SSRF via goroutine
func Handler00065(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("webhook")
	go func() {
		http.Get(target)
	}()
	w.WriteHeader(202)
}
