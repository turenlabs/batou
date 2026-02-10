package vulnerable

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// VULN: Weak cryptographic hash (MD5) and insecure random (math/rand) for token generation.
// Should trigger GTSS-CRY-001 (Weak Hashing) and GTSS-CRY-002 / GTSS-CRY-011 (Insecure Random / Predictable Seed).

func HandleResetToken(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	// Weak hash for password reset token
	hash := md5.Sum([]byte(email + time.Now().String()))
	token := hex.EncodeToString(hash[:])

	// Insecure random for session identifier
	rand.Seed(time.Now().UnixNano())
	sessionID := fmt.Sprintf("%016x", rand.Int63())

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":"%s","session":"%s"}`, token, sessionID)
}
