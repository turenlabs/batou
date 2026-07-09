package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Hardcoded JSON, no user input
func Handler00134(w http.ResponseWriter, r *http.Request) {
	raw := []byte(`{"status":"ok"}`)
	var data map[string]string
	json.Unmarshal(raw, &data)
	fmt.Fprintf(w, "status: %s", data["status"])
}
