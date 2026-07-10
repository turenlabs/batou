package bench

import (
	"net/http"
	htmltemplate "html/template"
)

// html/template auto-escaping
func Handler00093(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	t, _ := htmltemplate.New("t").Parse("<p>Hello {{.}}</p>")
	t.Execute(w, name)
}
