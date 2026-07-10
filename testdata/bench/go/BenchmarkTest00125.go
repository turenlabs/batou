package bench

import (
	"encoding/gob"
	"net/http"
)

// Unsafe gob decode in goroutine
func Handler00125(w http.ResponseWriter, r *http.Request) {
	go func() {
		var data interface{}
		gob.NewDecoder(r.Body).Decode(&data)
	}()
}
