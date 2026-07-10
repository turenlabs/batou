package bench

import (
	"net/http"
	"net/url"
)

// URL parse + host check
func Handler00153(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Host != "" && parsed.Host != "example.com") {
		http.Error(w, "forbidden", 403)
		return
	}
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}
