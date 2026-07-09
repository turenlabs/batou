package bench

import (
	"io"
	"net/http"
	"strconv"
)

// Integer-based endpoint selection
func Handler00080(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("svc")
	idx, _ := strconv.Atoi(raw)
	endpoints := []string{"https://svc1.internal", "https://svc2.internal"}
	if idx < 0 || idx >= len(endpoints) {
		http.Error(w, "bad index", 400)
		return
	}
	resp, _ := http.Get(endpoints[idx])
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
