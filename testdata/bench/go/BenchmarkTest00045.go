package bench

import (
	"net/http"
	"os"
)

// Path traversal via channel
func Handler00045(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("doc")
	ch := make(chan string, 1)
	ch <- name
	doc := <-ch
	data, _ := os.ReadFile("/docs/" + doc)
	w.Write(data)
}
