package bench

import (
	"net/http"
)

// Hardcoded in goroutine
func Handler00075(w http.ResponseWriter, r *http.Request) {
	go func() {
		http.Get("https://hooks.example.com/notify")
	}()
	w.WriteHeader(202)
}
