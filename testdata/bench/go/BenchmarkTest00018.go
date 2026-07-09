package bench

import (
	"database/sql"
	"net/http"
)

// Parameterized in goroutine
func Handler00018(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("name")
	db, _ := sql.Open("sqlite3", ":memory:")
	go func() {
		db.Exec("INSERT INTO log (name) VALUES (?)", param)
	}()
}
