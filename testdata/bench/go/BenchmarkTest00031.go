package bench

import (
	"net/http"
	"os/exec"
)

// Fixed command with no user args
func Handler00031(w http.ResponseWriter, r *http.Request) {
	exec.Command("ls", "-la", "/tmp").Run()
}
