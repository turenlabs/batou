package bench

import (
	"io"
	"net/http"
)

// SSRF via http.Post
func Handler00062(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("endpoint")
	resp, _ := http.Post(target, "application/json", r.Body)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
