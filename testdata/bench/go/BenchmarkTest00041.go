package bench

import (
	"io"
	"net/http"
	"os"
)

// Path traversal via os.Open
func Handler00041(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	f, _ := os.Open(filename)
	defer f.Close()
	io.Copy(w, f)
}
