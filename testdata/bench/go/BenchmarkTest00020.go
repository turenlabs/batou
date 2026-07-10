package bench

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

// Query with integer format only
func Handler00020(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(raw)
	db, _ := sql.Open("sqlite3", ":memory:")
	query := fmt.Sprintf("SELECT * FROM items LIMIT %d", limit)
	db.Query(query)
}
