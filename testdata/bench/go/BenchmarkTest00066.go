package bench

import (
	"io"
	"net/http"
)

// SSRF via Header value
func Handler00066(w http.ResponseWriter, r *http.Request) {
	callback := r.Header.Get("X-Callback-URL")
	resp, _ := http.Get(callback)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
