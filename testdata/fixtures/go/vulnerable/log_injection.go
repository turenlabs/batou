package vulnerable

import (
	"log"
	"net/http"
)

// VULN: Log injection - unsanitized user input written directly to log.
// Should trigger GTSS-LOG-001 (Unsanitized User Input in Log Calls).

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Attacker can inject newlines: username = "admin\n[INFO] Login successful for admin"
	log.Printf("Login attempt for user: %s from IP: %s", username, r.RemoteAddr)

	if !authenticate(username, password) {
		log.Printf("Failed login for user: %s", r.FormValue("username"))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	log.Printf("Successful login for user: %s", username)
	w.Write([]byte("welcome"))
}

func authenticate(user, pass string) bool {
	return user == "admin" && pass == "admin"
}
