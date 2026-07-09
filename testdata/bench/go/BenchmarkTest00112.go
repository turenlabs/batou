package bench

import (
	"net/http"
	htmltemplate "html/template"
)

// html/template auto-escaping
func Handler00112(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	t, _ := htmltemplate.New("t").Parse("<h1>Hello {{.}}</h1>")
	t.Execute(w, name)
}
