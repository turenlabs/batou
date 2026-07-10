package bench

import (
	"net/http"
	"os"
)

// Path traversal via os.Remove
func Handler00047(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("delete")
	os.Remove(file)
}
