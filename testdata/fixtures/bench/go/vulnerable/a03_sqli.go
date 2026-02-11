// Source: CWE-89 - SQL Injection in Go web handler
// Expected: GTSS-INJ-001 (SQL Injection via fmt.Sprintf)
// OWASP: A03:2021 - Injection (SQL Injection)

package handler

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

func SearchUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	sqlQuery := fmt.Sprintf("SELECT id, username, email FROM users WHERE username LIKE '%%%s%%'", query)
	rows, err := db.Query(sqlQuery)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var username, email string
		rows.Scan(&id, &username, &email)
		fmt.Fprintf(w, "User: %s (%s)\n", username, email)
	}
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT username, email FROM users WHERE id = " + userID)
	var username, email string
	if err := row.Scan(&username, &email); err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, `{"username":"%s","email":"%s"}`, username, email)
}
