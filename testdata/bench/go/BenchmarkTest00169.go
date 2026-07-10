package bench

import (
	"log"
	"net/http"
)

// Log injection via Cookie
func Handler00169(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_id")
	log.Printf("Session: %s", cookie.Value)
}
