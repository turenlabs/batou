package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via multiple hops
func Handler00030(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("prog")
	prog := raw
	arg := "--version"
	exec.Command(prog, arg).Run()
}
