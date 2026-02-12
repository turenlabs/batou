package main

import (
	"fmt"
	"net/http"
)

// VULNERABLE: GraphQL query built with fmt.Sprintf
func handleGraphQL(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("query { user(id: \"%s\") { name email } }", userID)
	_ = query
}
