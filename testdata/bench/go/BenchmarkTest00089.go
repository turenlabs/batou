package bench

import (
	"net/http"
	"text/template"
)

// Template injection via multiple vars
func Handler00089(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("tmpl")
	userTmpl := raw
	t, _ := template.New("t").Parse(userTmpl)
	t.Execute(w, nil)
}
