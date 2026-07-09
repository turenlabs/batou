package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Typed struct via channel
type safeCh135 struct {
	Msg string `json:"msg"`
}

func Handler00135(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ch := make(chan []byte, 1)
	ch <- body
	raw := <-ch
	var msg safeCh135
	json.Unmarshal(raw, &msg)
	fmt.Fprintf(w, "msg: %s", msg.Msg)
}
