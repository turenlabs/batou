package bench

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

// Unsafe XML decode from request
func Handler00123(w http.ResponseWriter, r *http.Request) {
	var data interface{}
	xml.NewDecoder(r.Body).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}
