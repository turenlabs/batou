package bench

import (
	"log"
	"net/http"
)

// Hardcoded log via channel
func Handler00175(w http.ResponseWriter, r *http.Request) {
	ch := make(chan string, 1)
	ch <- "startup"
	msg := <-ch
	log.Printf("Event: %s", msg)
}
