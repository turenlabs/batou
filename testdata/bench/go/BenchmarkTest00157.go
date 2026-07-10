package bench

import (
	"net/http"
	"net/url"
)

// Path-only redirect with url.Parse
func Handler00157(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("next")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() {
		http.Error(w, "bad redirect", 400)
		return
	}
	http.Redirect(w, r, parsed.Path, http.StatusFound)
}
