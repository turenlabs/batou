package safe

import (
	"net/http"
	"os/exec"
	"regexp"
)

// SAFE: Command execution without shell interpreter - arguments passed separately.
// Should NOT trigger GTSS-INJ-002.

var validHostname = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$`)

func HandlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// Validate hostname format before use
	if !validHostname.MatchString(host) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}

	// Safe: arguments are separate, no shell interpreter involved
	cmd := exec.Command("ping", "-c", "3", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

func HandleListFiles(w http.ResponseWriter, r *http.Request) {
	// Safe: hardcoded arguments, no user input in command
	cmd := exec.Command("ls", "-la", "/var/log")
	output, _ := cmd.CombinedOutput()
	w.Write(output)
}
