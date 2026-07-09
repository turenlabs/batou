package bench

import (
	"io"
	"net/http"
)

// SSRF via string concat URL
func Handler00067(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	target := "http://" + host + "/api/data"
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
