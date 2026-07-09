package bench

import (
	"net/http"
	"text/template"
)

// Template from embedded string
func Handler00100(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	const tmpl = "Message: {{.}}"
	t, _ := template.New("t").Parse(tmpl)
	t.Execute(w, msg)
}
