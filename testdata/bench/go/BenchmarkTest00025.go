package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via Header
func Handler00025(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	exec.Command("echo", userAgent).Output()
}
