package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via goroutine
func Handler00024(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("target")
	go func() {
		exec.Command("nslookup", target).Run()
	}()
}
