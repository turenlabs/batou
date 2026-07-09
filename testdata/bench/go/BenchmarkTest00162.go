package bench

import (
	"log"
	"net/http"
)

// Log injection via log.Println
func Handler00162(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	log.Println("Action performed: " + action)
}
