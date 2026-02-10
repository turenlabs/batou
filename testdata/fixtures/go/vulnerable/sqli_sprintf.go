package vulnerable

import (
	"database/sql"
	"fmt"
	"net/http"
)

// VULN: SQL injection via fmt.Sprintf with user input in query string.
// Should trigger GTSS-INJ-001 (SQL Injection).

func HandleUserLookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	username := r.FormValue("username")

	query := fmt.Sprintf("SELECT id, email FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var email string
		rows.Scan(&id, &email)
		fmt.Fprintf(w, "ID: %d, Email: %s\n", id, email)
	}
}
