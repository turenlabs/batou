package bench

import (
	"log"
	"net/http"
)

// Hardcoded in goroutine
func Handler00176(w http.ResponseWriter, r *http.Request) {
	go func() {
		log.Println("Background task started")
	}()
}
