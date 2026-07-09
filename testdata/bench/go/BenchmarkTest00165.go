package bench

import (
	"log"
	"net/http"
)

// Log injection via goroutine
func Handler00165(w http.ResponseWriter, r *http.Request) {
	ip := r.Header.Get("X-Forwarded-For")
	go func() {
		log.Printf("Request from: %s", ip)
	}()
}
