package bench

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"strings"
)

// Unsafe gob from PostFormValue
func Handler00129(w http.ResponseWriter, r *http.Request) {
	raw := r.PostFormValue("payload")
	var data interface{}
	gob.NewDecoder(strings.NewReader(raw)).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}
