package bench

import (
	"net/http"
	"os/exec"
	"strings"
)

// Fixed binary, user data via pipe not arg
func Handler00040(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("text")
	c := exec.Command("grep", "pattern")
	c.Stdin = strings.NewReader(input)
	c.Run()
}
