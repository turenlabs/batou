package bench

import (
	"encoding/json"
	"io"
	"net/http"
)

// Typed struct with defer
type safeDefer138 struct {
	Key string `json:"key"`
}

func Handler00138(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var item safeDefer138
	defer func() {
		json.Unmarshal(body, &item)
	}()
}
