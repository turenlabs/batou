package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Unsafe JSON unmarshal to interface{}
func Handler00121(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var data interface{}
	json.Unmarshal(body, &data)
	fmt.Fprintf(w, "got: %v", data)
}
