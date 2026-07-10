package bench

import (
	"log"
	"net/http"
)

// Log injection via channel
func Handler00164(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("data")
	ch := make(chan string, 1)
	ch <- input
	data := <-ch
	log.Printf("Received data: %s", data)
}
