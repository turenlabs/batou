package bench

import (
	"log"
	"net/http"
	"strconv"
)

// Sanitized via strconv
func Handler00174(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("count")
	count, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return
	}
	log.Printf("Count: %d", count)
}
