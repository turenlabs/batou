package bench

import (
	"net/http"
	"os/exec"
)

// Command with validated allowlist
func Handler00032(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	allowed := map[string]bool{"date": true, "uptime": true, "whoami": true}
	if !allowed[tool] {
		http.Error(w, "not allowed", 400)
		return
	}
	exec.Command(tool).Run()
}
