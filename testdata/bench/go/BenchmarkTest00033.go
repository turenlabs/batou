package bench

import (
	"net/http"
	"os/exec"
	"strings"
)

// Fixed command, user input only in stdin
func Handler00033(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	c := exec.Command("wc", "-l")
	c.Stdin = strings.NewReader(data)
	c.Run()
}
