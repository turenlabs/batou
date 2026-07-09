package bench

import (
	"net/http"
	"os/exec"
)

// Hardcoded echo
func Handler00039(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("ignored")
	exec.Command("echo", "hello world").Run()
}
