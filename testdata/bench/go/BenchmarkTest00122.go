package bench

import (
	"encoding/gob"
	"fmt"
	"net/http"
)

// Unsafe gob decode from request
func Handler00122(w http.ResponseWriter, r *http.Request) {
	var data interface{}
	gob.NewDecoder(r.Body).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}
