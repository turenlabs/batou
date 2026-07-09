package bench

import (
	"database/sql"
	"net/http"
)

// Prepared statement
func Handler00014(w http.ResponseWriter, r *http.Request) {
	param := r.FormValue("search")
	db, _ := sql.Open("sqlite3", ":memory:")
	stmt, _ := db.Prepare("SELECT * FROM items WHERE name = ?")
	stmt.Query(param)
}
