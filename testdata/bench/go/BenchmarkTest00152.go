package bench

import (
	"net/http"
	"strings"
)

// Relative path only via HasPrefix
func Handler00152(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		http.Error(w, "bad redirect", 400)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}
