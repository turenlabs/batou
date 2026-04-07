package safe

import (
	"log/slog"
	"net/http"
	"strings"
)

// SAFE: Structured logging with sanitized input fields.
// Should NOT trigger BATOU-LOG-001 or any log injection rules.

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	username := sanitizeLogField(r.FormValue("username"))
	action := sanitizeLogField(r.FormValue("action"))

	// Safe: structured logging with sanitized values
	slog.Info("login attempt",
		"username", username,
		"action", action,
		"ip", r.RemoteAddr,
	)

	slog.Warn("failed login",
		"username", username,
		"ip", r.RemoteAddr,
	)
}

func sanitizeLogField(input string) string {
	// Remove newlines and control characters to prevent log injection
	s := strings.ReplaceAll(input, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	s = strings.ReplaceAll(s, "\t", "_")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
