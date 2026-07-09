package bench

import (
	"net/http"
)

// Hardcoded with defer
func Handler00078(w http.ResponseWriter, r *http.Request) {
	defer http.Get("https://metrics.internal/ping")
	w.WriteHeader(200)
}
