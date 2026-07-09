package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Typed struct from query param
type safeQuery140 struct {
	Filter string `json:"filter"`
}

func Handler00140(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("data")
	var filter safeQuery140
	json.Unmarshal([]byte(raw), &filter)
	fmt.Fprintf(w, "filter: %s", filter.Filter)
}
