package bench

import (
	"database/sql"
	"net/http"
)

// Parameterized with channel
func Handler00017(w http.ResponseWriter, r *http.Request) {
	param := r.FormValue("id")
	ch := make(chan string, 1)
	ch <- param
	val := <-ch
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE id = ?", val)
}
