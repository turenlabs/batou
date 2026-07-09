package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via defer
func Handler00006(w http.ResponseWriter, r *http.Request) {
	param := r.PostFormValue("table")
	db, _ := sql.Open("sqlite3", ":memory:")
	query := "DROP TABLE " + param
	defer db.Exec(query)
}
