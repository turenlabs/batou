package bench

import (
	"log"
	"net/http"
	"strconv"
)

// Log with format verb %d only
func Handler00177(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(raw)
	log.Printf("Serving page %d", page)
}
