package bench

import (
	"io"
	"net/http"
)

// Hardcoded URL
func Handler00071(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get("https://api.example.com/data")
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
