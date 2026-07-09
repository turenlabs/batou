package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via string concat in shell
func Handler00026(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	exec.Command("sh", "-c", "ls -la "+dir).Run()
}
