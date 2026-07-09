package bench

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
)

// Integer-based file lookup
func Handler00054(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("id")
	id, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	path := fmt.Sprintf("/data/files/%d.dat", id)
	data, _ := os.ReadFile(path)
	w.Write(data)
}
