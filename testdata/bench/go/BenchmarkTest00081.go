package bench

import (
	"net/http"
	"text/template"
)

// Template injection via text/template Parse
func Handler00081(w http.ResponseWriter, r *http.Request) {
	tmplStr := r.FormValue("template")
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, nil)
}
