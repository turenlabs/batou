package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via multiple assignments
func Handler00008(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("filter")
	filter := raw
	clause := "WHERE status = '" + filter + "'"
	query := "SELECT * FROM orders " + clause
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query(query)
}
