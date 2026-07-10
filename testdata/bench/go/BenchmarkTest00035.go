package bench

import (
	"net/http"
	"os/exec"
)

// Hardcoded args, goroutine
func Handler00035(w http.ResponseWriter, r *http.Request) {
	go func() {
		exec.Command("date", "+%Y-%m-%d").Run()
	}()
}
