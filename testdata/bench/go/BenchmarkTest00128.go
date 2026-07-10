package bench

import (
	"encoding/json"
	"io"
	"net/http"
)

// Unsafe JSON decode with defer
func Handler00128(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var data interface{}
	defer func() {
		json.Unmarshal(body, &data)
	}()
}
