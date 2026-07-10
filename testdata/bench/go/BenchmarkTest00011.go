package bench

import (
	"database/sql"
	"net/http"
)

// Parameterized query
func Handler00011(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("id")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE id = ?", param)
}
