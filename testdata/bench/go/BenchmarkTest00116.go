package bench

import (
	"net/http"
	htmltemplate "html/template"
)

// html/template in goroutine
func Handler00116(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	go func() {
		t, _ := htmltemplate.New("t").Parse("<p>{{.}}</p>")
		t.Execute(w, name)
	}()
}
