package bench

import (
	"net/http"
	"text/template"
)

// Precompiled template
func Handler00092(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmpl := template.Must(template.New("t").Parse("<p>Welcome {{.}}</p>"))
	tmpl.Execute(w, name)
}
