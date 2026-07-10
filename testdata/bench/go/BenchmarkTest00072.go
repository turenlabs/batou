package bench

import (
	"io"
	"net/http"
	"net/url"
)

// URL parse + host allowlist
func Handler00072(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host != "api.trusted.com" {
		http.Error(w, "forbidden", 403)
		return
	}
	resp, _ := http.Get(parsed.String())
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
