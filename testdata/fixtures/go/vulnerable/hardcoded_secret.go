package vulnerable

import (
	"database/sql"
	"net/http"

	_ "github.com/lib/pq"
)

// VULN: Hardcoded credentials in source code.
// Should trigger GTSS-SEC-001 (Hardcoded Password) and GTSS-SEC-004 (Connection String).

var apiKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

var secret = "mySuperSecretKey2024!@#"

func ConnectDB() (*sql.DB, error) {
	connStr := "postgres://admin:p4ssw0rd_prod!@db.internal.example.com:5432/appdb?sslmode=disable"
	return sql.Open("postgres", connStr)
}

func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "Bearer "+apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("OK"))
}
