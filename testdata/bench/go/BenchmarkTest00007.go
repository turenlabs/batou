package bench

import (
	"database/sql"
	"net/http"
)

// SQL injection via Header.Get
func Handler00007(w http.ResponseWriter, r *http.Request) {
	tenant := r.Header.Get("X-Tenant-ID")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM data WHERE tenant = '" + tenant + "'")
}
