package bench

import (
	"fmt"
	"net/http"
	"strconv"
)

// Integer-based page redirect
func Handler00158(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(raw)
	dest := fmt.Sprintf("/results?page=%d", page)
	http.Redirect(w, r, dest, http.StatusFound)
}
