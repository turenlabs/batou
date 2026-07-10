package bench

import (
	"database/sql"
	"net/http"
)

// Parameterized Exec
func Handler00012(w http.ResponseWriter, r *http.Request) {
	param := r.FormValue("name")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec("INSERT INTO users (name) VALUES (?)", param)
}
