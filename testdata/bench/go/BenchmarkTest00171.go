package bench

import (
	"log"
	"net/http"
	"strings"
)

// Structured logging with sanitized field
func Handler00171(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	safe := strings.ReplaceAll(user, "\n", "")
	safe = strings.ReplaceAll(safe, "\r", "")
	log.Printf("Login attempt: user=%s", safe)
}
