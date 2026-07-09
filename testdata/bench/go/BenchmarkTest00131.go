package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Typed struct unmarshal
type safeUser131 struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func Handler00131(w http.ResponseWriter, r *http.Request) {
	var user safeUser131
	json.NewDecoder(r.Body).Decode(&user)
	fmt.Fprintf(w, "name: %s", user.Name)
}
