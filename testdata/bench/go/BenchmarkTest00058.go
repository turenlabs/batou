package bench

import (
	"net/http"
	"os"
	"path/filepath"
)

// filepath.Base via channel
func Handler00058(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	ch := make(chan string, 1)
	ch <- filepath.Base(name)
	safe := <-ch
	data, _ := os.ReadFile(filepath.Join("/uploads", safe))
	w.Write(data)
}
