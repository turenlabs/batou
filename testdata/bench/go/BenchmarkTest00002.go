package bench

import (
	"database/sql"
	"fmt"
	"net/http"
)

// SQL injection via fmt.Sprintf
func Handler00002(w http.ResponseWriter, r *http.Request) {
	param := r.FormValue("name")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", param)
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec(query)
}
