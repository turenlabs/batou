package bench

import (
	"encoding/json"
	"net/http"
)

// No template at all, plain write
func Handler00097(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"name": name})
}
