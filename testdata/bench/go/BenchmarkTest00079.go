package bench

import (
	"io"
	"net/http"
	"net/url"
)

// URL parse sanitizer
func Handler00079(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("url")
	parsed, err := url.Parse(raw)
	if err != nil {
		http.Error(w, "bad url", 400)
		return
	}
	allowed := map[string]bool{"api.example.com": true}
	if !allowed[parsed.Host] {
		http.Error(w, "forbidden", 403)
		return
	}
	resp, _ := http.Get(parsed.String())
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
