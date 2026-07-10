package bench

import (
	"database/sql"
	"net/http"
)

// Parameterized QueryRow
func Handler00013(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("email")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.QueryRow("SELECT id FROM users WHERE email = ?", param)
}
