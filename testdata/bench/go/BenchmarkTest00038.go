package bench

import (
	"net/http"
	"os/exec"
	"regexp"
)

// Regex-validated input
func Handler00038(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", name)
	if !matched {
		http.Error(w, "invalid", 400)
		return
	}
	exec.Command("echo", name).Run()
}
