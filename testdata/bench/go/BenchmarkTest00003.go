package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via QueryRow with concat
func Handler00003(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("email")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.QueryRow("SELECT id FROM users WHERE email = '" + param + "'")
}
