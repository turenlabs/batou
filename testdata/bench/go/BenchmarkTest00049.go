package bench

import (
	"net/http"
	"os"
)

// Path traversal via defer
func Handler00049(w http.ResponseWriter, r *http.Request) {
	tmp := r.FormValue("tmp")
	defer os.Remove(tmp)
	data, _ := os.ReadFile(tmp)
	w.Write(data)
}
