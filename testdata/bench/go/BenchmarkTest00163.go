package bench

import (
	"log"
	"net/http"
	"os"
)

// Log injection via fmt.Fprintf to logger
func Handler00163(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	logger := log.New(os.Stderr, "APP: ", log.LstdFlags)
	logger.Printf("User message: %s", msg)
}
