package bench

import (
	"net/http"
	"text/template"
)

// Fixed template in goroutine
func Handler00096(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	go func() {
		t, _ := template.New("t").Parse("Name: {{.}}")
		t.Execute(w, name)
	}()
}
