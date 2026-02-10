package safe

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// SAFE: Strong cryptographic hash (bcrypt) and secure random (crypto/rand).
// Should NOT trigger GTSS-CRY-001 or GTSS-CRY-002.

func HandleRegister(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")

	// Safe: bcrypt for password hashing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_ = hashedPassword // store in database
	w.Write([]byte("registered"))
}

func GenerateSecureToken() (string, error) {
	// Safe: crypto/rand for token generation
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HandleResetToken(w http.ResponseWriter, r *http.Request) {
	token, err := GenerateSecureToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, `{"token":"%s"}`, token)
}
