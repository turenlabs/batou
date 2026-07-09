package bench

import (
	"encoding/json"
	"io"
	"net/http"
)

// Typed struct in goroutine
type safeGo136 struct {
	Action string `json:"action"`
}

func Handler00136(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	go func() {
		var act safeGo136
		json.Unmarshal(body, &act)
	}()
}
