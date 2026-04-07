package vulnerable

import (
	"database/sql"
	"fmt"
	"net/http"
)

// VULN: SQL injection via string concatenation in db.Query.
// Should trigger BATOU-INJ-001 (SQL Injection).

func HandleSearch(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	term := r.URL.Query().Get("q")

	query := "SELECT title, body FROM articles WHERE title LIKE '%" + term + "%'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var title, body string
		rows.Scan(&title, &body)
		fmt.Fprintf(w, "<h2>%s</h2><p>%s</p>", title, body)
	}
}
