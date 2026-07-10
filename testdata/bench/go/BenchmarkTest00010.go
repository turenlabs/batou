package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via Cookie
func Handler00010(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_data")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM sessions WHERE data = '" + cookie.Value + "'")
}
