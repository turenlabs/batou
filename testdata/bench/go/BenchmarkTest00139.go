package bench

import (
	"encoding/gob"
	"fmt"
	"net/http"
)

// Typed gob decode
type safeGob139 struct {
	Value int
}

func Handler00139(w http.ResponseWriter, r *http.Request) {
	var val safeGob139
	gob.NewDecoder(r.Body).Decode(&val)
	fmt.Fprintf(w, "value: %d", val.Value)
}
