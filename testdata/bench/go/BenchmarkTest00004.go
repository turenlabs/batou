package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via channel propagation
func Handler00004(w http.ResponseWriter, r *http.Request) {
	param := r.FormValue("search")
	ch := make(chan string, 1)
	ch <- param
	tainted := <-ch
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM items WHERE name = '" + tainted + "'")
}
