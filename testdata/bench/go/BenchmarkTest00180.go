package bench

import (
	"log"
	"net/http"
)

// Quoted/escaped log output
func Handler00180(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	log.Printf("Login attempt: user=%q", user)
}
