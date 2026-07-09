package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via defer
func Handler00027(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	defer exec.Command("rm", path).Run()
}
