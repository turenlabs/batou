package vulnerable

import (
	"encoding/gob"
	"encoding/json"
	"net/http"
)

// VULN: Unsafe deserialization from untrusted HTTP request body.
// Should trigger taint analysis for go.json.decoder.decode sink with user input source.

type UserProfile struct {
	Name    string
	Email   string
	IsAdmin bool
	Role    string
}

func HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	var profile UserProfile

	// JSON decode from untrusted request body - attacker can set IsAdmin: true
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&profile); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Gob decode from untrusted source
	var data map[string]interface{}
	gobDecoder := gob.NewDecoder(r.Body)
	gobDecoder.Decode(&data)

	w.Write([]byte("profile updated"))
}
