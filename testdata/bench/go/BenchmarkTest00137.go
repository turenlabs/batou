package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Map[string]string typed decode
func Handler00137(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	json.NewDecoder(r.Body).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}
