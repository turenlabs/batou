package bench

import (
	"net/http"
	"os/exec"
)

// Hardcoded command via channel
func Handler00036(w http.ResponseWriter, r *http.Request) {
	ch := make(chan string, 1)
	ch <- "hostname"
	cmd := <-ch
	_ = cmd
	exec.Command("hostname").Run()
}
