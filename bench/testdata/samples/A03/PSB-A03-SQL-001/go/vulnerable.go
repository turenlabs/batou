// PSB-A03-SQL-001: User search endpoint
// CWE: CWE-89
// Expected: GTSS-INJ-001, GTSS-INJ-002
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func searchUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Error(w, `{"error":"query parameter 'q' is required"}`, http.StatusBadRequest)
		return
	}

	query := fmt.Sprintf("SELECT id, name, email FROM users WHERE name LIKE '%%%s%%'", q)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type User struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email); err == nil {
			users = append(users, u)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
