package bench

import (
	"io"
	"net/http"
)

// Allowlist map check
func Handler00074(w http.ResponseWriter, r *http.Request) {
	svc := r.FormValue("service")
	endpoints := map[string]string{"users": "http://users-svc:8080", "orders": "http://orders-svc:8080"}
	target, ok := endpoints[svc]
	if !ok {
		http.Error(w, "unknown service", 400)
		return
	}
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
