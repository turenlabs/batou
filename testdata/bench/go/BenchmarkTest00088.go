package bench

import (
	"net/http"
	"text/template"
)

// Template injection via defer
func Handler00088(w http.ResponseWriter, r *http.Request) {
	tmplStr := r.FormValue("footer")
	t, _ := template.New("t").Parse(tmplStr)
	defer t.Execute(w, nil)
}
