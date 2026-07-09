package bench

import (
	"net/http"
	"text/template"
)

// Template injection via goroutine
func Handler00084(w http.ResponseWriter, r *http.Request) {
	tmplStr := r.URL.Query().Get("layout")
	go func() {
		t, _ := template.New("t").Parse(tmplStr)
		t.Execute(w, nil)
	}()
}
