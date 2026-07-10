package bench

import (
	"net/http"
	htmltemplate "html/template"
)

// XSS via template.HTML bypass
func Handler00103(w http.ResponseWriter, r *http.Request) {
	content := r.FormValue("content")
	t, _ := htmltemplate.New("t").Parse("{{.}}")
	t.Execute(w, htmltemplate.HTML(content))
}
