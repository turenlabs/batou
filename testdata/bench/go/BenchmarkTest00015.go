package bench

import (
	"database/sql"
	"net/http"
	"strconv"
)

// Integer conversion sanitizer
func Handler00015(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("id")
	id, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE id = ?", id)
}
