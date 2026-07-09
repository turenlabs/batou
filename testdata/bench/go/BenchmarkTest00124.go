package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Unsafe JSON decode via channel
func Handler00124(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ch := make(chan []byte, 1)
	ch <- body
	raw := <-ch
	var data interface{}
	json.Unmarshal(raw, &data)
	fmt.Fprintf(w, "got: %v", data)
}
