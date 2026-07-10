package bench

import (
	"net/http"
	"text/template"
)

// Fixed template with defer
func Handler00098(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	t, _ := template.New("t").Parse("Goodbye {{.}}")
	defer t.Execute(w, name)
}
