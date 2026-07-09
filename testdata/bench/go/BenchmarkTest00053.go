package bench

import (
	"net/http"
	"os"
)

// Hardcoded path, no user input
func Handler00053(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile("/etc/config.json")
	w.Write(data)
}
