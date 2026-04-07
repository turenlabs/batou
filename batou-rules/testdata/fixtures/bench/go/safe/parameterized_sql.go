package safe

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
)

// SAFE: Parameterized query with database/sql placeholder $1
func GetUserByID(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		row := db.QueryRow(
			"SELECT id, name, email FROM users WHERE id = $1 AND active = true",
			userID,
		)
		var id int
		var name, email string
		if err := row.Scan(&id, &name, &email); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": id, "name": name, "email": email,
		})
	}
}

// SAFE: Parameterized INSERT
func CreateUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")
		email := r.FormValue("email")
		var id int
		err := db.QueryRow(
			"INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id",
			name, email,
		).Scan(&id)
		if err != nil {
			http.Error(w, "insert failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]int{"id": id})
	}
}

// SAFE: Parameterized search with LIMIT
func SearchProducts(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		term := r.URL.Query().Get("q")
		limitStr := r.URL.Query().Get("limit")
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			limit = 20
		}
		rows, err := db.Query(
			"SELECT id, name, price FROM products WHERE name ILIKE $1 ORDER BY name LIMIT $2",
			"%"+term+"%", limit,
		)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type product struct {
			ID    int     `json:"id"`
			Name  string  `json:"name"`
			Price float64 `json:"price"`
		}
		var results []product
		for rows.Next() {
			var p product
			rows.Scan(&p.ID, &p.Name, &p.Price)
			results = append(results, p)
		}
		json.NewEncoder(w).Encode(results)
	}
}
