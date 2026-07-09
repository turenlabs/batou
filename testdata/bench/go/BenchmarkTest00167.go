package bench

import (
	"log"
	"net/http"
)

// Log injection via PostFormValue
func Handler00167(w http.ResponseWriter, r *http.Request) {
	comment := r.PostFormValue("comment")
	log.Printf("New comment: %s", comment)
}
