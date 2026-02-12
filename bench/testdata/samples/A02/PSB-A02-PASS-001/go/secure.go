// PSB-A02-PASS-001: Password storage/registration
// CWE: CWE-916, CWE-328
// Expected: (none - secure)
package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	json.NewDecoder(r.Body).Decode(&req)

	emailRe := regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
	if !emailRe.MatchString(req.Email) {
		http.Error(w, `{"error":"invalid email"}`, http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, `{"error":"password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	db.Exec("INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
		req.Username, req.Email, string(hashed))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"username": req.Username,
		"email":    req.Email,
	})
}
