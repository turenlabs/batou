package bench

import (
	"io"
	"net/http"
	"net/url"
)

// Path-only user input, fixed host
func Handler00073(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	target := "https://internal.api.com/" + url.PathEscape(path)
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
