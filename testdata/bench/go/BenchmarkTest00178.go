package bench

import (
	"log"
	"net/http"
)

// Hardcoded with defer
func Handler00178(w http.ResponseWriter, r *http.Request) {
	defer log.Println("Request completed")
}
