package bench

import (
	"encoding/json"
	"net/http"
)

// JSON response, no HTML
func Handler00113(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"name": name})
}
