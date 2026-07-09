package bench

import (
	"database/sql"
	"net/http"
)

// Hardcoded query, no user input
func Handler00016(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE active = true")
}
