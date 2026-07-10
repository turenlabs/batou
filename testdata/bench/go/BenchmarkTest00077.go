package bench

import (
	"io"
	"net/http"
)

// Fixed URL via channel
func Handler00077(w http.ResponseWriter, r *http.Request) {
	ch := make(chan string, 1)
	ch <- "https://safe.example.com/data"
	target := <-ch
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
