package bench

import (
	"net/http"
	"text/template"
)

// Template injection via concatenation
func Handler00086(w http.ResponseWriter, r *http.Request) {
	header := r.FormValue("header")
	tmplStr := "<h1>" + header + "</h1>{{.Body}}"
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, map[string]string{"Body": "content"})
}
