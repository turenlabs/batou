package bench

import (
	"fmt"
	"net/http"
	"strconv"
)

// Integer-only output
func Handler00118(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("count")
	count, _ := strconv.Atoi(raw)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Count: %d</p>", count)
}
