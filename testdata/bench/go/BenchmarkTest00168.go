package bench

import (
	"log"
	"net/http"
)

// Log injection via defer
func Handler00168(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	defer log.Printf("Served path: %s", path)
}
