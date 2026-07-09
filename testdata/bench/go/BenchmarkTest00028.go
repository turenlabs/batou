package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via PostFormValue
func Handler00028(w http.ResponseWriter, r *http.Request) {
	script := r.PostFormValue("script")
	exec.Command("bash", "-c", script).CombinedOutput()
}
