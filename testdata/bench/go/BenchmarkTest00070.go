package bench

import (
	"io"
	"net/http"
)

// SSRF via Cookie
func Handler00070(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("api_endpoint")
	resp, _ := http.Get(cookie.Value)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
