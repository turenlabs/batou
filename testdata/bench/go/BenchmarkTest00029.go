package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via Cookie
func Handler00029(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("tool")
	exec.Command(cookie.Value).Run()
}
