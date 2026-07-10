package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Unsafe YAML-like decode from query
func Handler00127(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("config")
	var data interface{}
	json.Unmarshal([]byte(raw), &data)
	fmt.Fprintf(w, "got: %v", data)
}
