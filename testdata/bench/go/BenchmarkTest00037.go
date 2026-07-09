package bench

import (
	"net/http"
	"os/exec"
)

// Fixed command with defer
func Handler00037(w http.ResponseWriter, r *http.Request) {
	defer exec.Command("sync").Run()
}
