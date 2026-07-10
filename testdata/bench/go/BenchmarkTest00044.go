package bench

import (
	"io"
	"net/http"
	"os"
)

// Path traversal via os.Create
func Handler00044(w http.ResponseWriter, r *http.Request) {
	dest := r.FormValue("dest")
	f, _ := os.Create(dest)
	defer f.Close()
	io.Copy(f, r.Body)
}
