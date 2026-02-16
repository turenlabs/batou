package vulnerable

import (
	"net/http"
	"os/exec"
)

// VULN: Command injection via exec.Command with shell interpreter and user input.
// Should trigger BATOU-INJ-002 (Command Injection).

func HandlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}
