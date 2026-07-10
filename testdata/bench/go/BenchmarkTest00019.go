package bench

import (
	"database/sql"
	"net/http"
)

// Parameterized with defer
func Handler00019(w http.ResponseWriter, r *http.Request) {
	param := r.PostFormValue("id")
	db, _ := sql.Open("sqlite3", ":memory:")
	stmt, _ := db.Prepare("DELETE FROM temp WHERE id = ?")
	defer stmt.Exec(param)
}
