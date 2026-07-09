package bench

import (
	"io"
	"net/http"
)

// SSRF via http.Get
func Handler00061(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
