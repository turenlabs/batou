package bench

import (
	"io"
	"net/http"
)

// SSRF via http.NewRequest
func Handler00063(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("api")
	req, _ := http.NewRequest("GET", target, nil)
	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
