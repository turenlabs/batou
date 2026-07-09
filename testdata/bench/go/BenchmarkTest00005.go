package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via goroutine
func Handler00005(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("sort")
	db, _ := sql.Open("sqlite3", ":memory:")
	go func() {
		query := "SELECT * FROM items ORDER BY " + param
		db.Query(query)
	}()
}
