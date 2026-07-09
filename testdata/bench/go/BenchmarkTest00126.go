package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Unsafe JSON decode via Header body
func Handler00126(w http.ResponseWriter, r *http.Request) {
	raw := r.Header.Get("X-Payload")
	var data interface{}
	json.Unmarshal([]byte(raw), &data)
	fmt.Fprintf(w, "got: %v", data)
}
