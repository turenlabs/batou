package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via variable assignment
func Handler00022(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	c := exec.Command("cat", filename)
	c.Run()
}
