package bench

import (
	"log"
	"net/http"
)

// Log injection via Header
func Handler00166(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	log.Printf("User-Agent: %s", ua)
}
