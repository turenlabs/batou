package bench

import (
	"log"
	"net/http"
	"strconv"
)

// Boolean-only log
func Handler00179(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("debug")
	debug, _ := strconv.ParseBool(raw)
	log.Printf("Debug mode: %t", debug)
}
