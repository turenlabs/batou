package bench

import (
	"io"
	"net/http"
)

// SSRF via channel propagation
func Handler00064(w http.ResponseWriter, r *http.Request) {
	rawURL := r.FormValue("fetch")
	ch := make(chan string, 1)
	ch <- rawURL
	target := <-ch
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
