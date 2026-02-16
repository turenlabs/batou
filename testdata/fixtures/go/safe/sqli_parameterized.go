package safe

import (
	"database/sql"
	"fmt"
	"net/http"
)

// SAFE: Parameterized SQL query - user input passed as bound parameter.
// Should NOT trigger BATOU-INJ-001.

func HandleUserLookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	username := r.FormValue("username")

	row := db.QueryRow("SELECT id, email FROM users WHERE username = $1", username)
	var id int
	var email string
	if err := row.Scan(&id, &email); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "ID: %d, Email: %s\n", id, email)
}

func HandleSearchSafe(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	term := r.URL.Query().Get("q")

	rows, err := db.Query("SELECT title, body FROM articles WHERE title ILIKE $1", "%"+term+"%")
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var title, body string
		rows.Scan(&title, &body)
		fmt.Fprintf(w, "Title: %s\n", title)
	}
}
