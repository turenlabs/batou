package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via string builder pattern
func Handler00009(w http.ResponseWriter, r *http.Request) {
	col := r.FormValue("column")
	val := r.FormValue("value")
	query := "SELECT * FROM products WHERE " + col + " = '" + val + "'"
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec(query)
}
