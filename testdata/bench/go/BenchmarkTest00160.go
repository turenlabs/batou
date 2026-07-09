package bench

import (
	"net/http"
	"net/url"
)

// Same-origin validated redirect
func Handler00160(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host != "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}
