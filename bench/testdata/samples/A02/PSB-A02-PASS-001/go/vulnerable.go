// PSB-A02-PASS-001: Password storage/registration
// CWE: CWE-916, CWE-328
// Expected: GTSS-CRYPTO-001, GTSS-CRYPTO-002
package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
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

	hash := md5.Sum([]byte(req.Password))
	hashed := hex.EncodeToString(hash[:])

	db.Exec("INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
		req.Username, req.Email, hashed)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"username": req.Username,
		"email":    req.Email,
	})
}
