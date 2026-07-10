package bench

import (
	"log"
	"net/http"
)

// Log injection via log.Printf
func Handler00161(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	log.Printf("Login attempt: user=%s", user)
}
