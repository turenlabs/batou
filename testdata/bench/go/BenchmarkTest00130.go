package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Unsafe JSON from Cookie
func Handler00130(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("state")
	var data interface{}
	json.Unmarshal([]byte(cookie.Value), &data)
	fmt.Fprintf(w, "got: %v", data)
}
