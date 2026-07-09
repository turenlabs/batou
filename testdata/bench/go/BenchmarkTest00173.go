package bench

import (
	"log"
	"net/http"
	"strconv"
)

// Integer-only log
func Handler00173(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(raw)
	log.Printf("Lookup id=%d", id)
}
