package bench

import (
	"net/http"
)

// Embed FS, no real file access
func Handler00055(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("file")
	w.Write([]byte("static content only"))
}
