package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via string concatenation
func Handler00001(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + param
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query(query)
}
