package bench

import (
	"io"
	"net/http"
	"os"
)

// Path traversal via Cookie value
func Handler00050(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("download")
	f, _ := os.Open(cookie.Value)
	defer f.Close()
	io.Copy(w, f)
}
