package bench

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Typed struct with validation
type safeReq132 struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func Handler00132(w http.ResponseWriter, r *http.Request) {
	var req safeReq132
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if req.ID <= 0 {
		http.Error(w, "bad id", 400)
		return
	}
	fmt.Fprintf(w, "id: %d", req.ID)
}
