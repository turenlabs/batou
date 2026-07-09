package bench

import (
	"log"
	"net/http"
)

// Log injection via multiple assignments
func Handler00170(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("ref")
	ref := raw
	log.Printf("Referrer: %s", ref)
}
