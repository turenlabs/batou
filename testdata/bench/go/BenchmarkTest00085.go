package bench

import (
	"net/http"
	"text/template"
)

// Template injection via Header
func Handler00085(w http.ResponseWriter, r *http.Request) {
	tmplStr := r.Header.Get("X-Template")
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, nil)
}
