package bench

import (
	"net/http"
	"os/exec"
	"strconv"
)

// Integer arg only
func Handler00034(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("count")
	count, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad count", 400)
		return
	}
	exec.Command("seq", strconv.Itoa(count)).Run()
}
