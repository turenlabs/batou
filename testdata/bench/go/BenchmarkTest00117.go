package bench

import (
	"fmt"
	"net/http"
)

// Hardcoded HTML, no user input
func Handler00117(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h1>Welcome</h1>")
}
