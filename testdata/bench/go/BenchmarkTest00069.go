package bench

import (
	"io"
	"net/http"
)

// SSRF via PostFormValue
func Handler00069(w http.ResponseWriter, r *http.Request) {
	target := r.PostFormValue("redirect_url")
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
