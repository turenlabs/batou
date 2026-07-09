package bench

import (
	"net/http"
	"os/exec"
)

// Command injection via channel
func Handler00023(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("host")
	ch := make(chan string, 1)
	ch <- input
	host := <-ch
	exec.Command("ping", host).Run()
}
