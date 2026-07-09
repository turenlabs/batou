package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via exec.Command
func Handler00021(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
