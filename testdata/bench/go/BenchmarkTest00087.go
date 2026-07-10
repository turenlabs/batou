package bench

import (
	"net/http"
	"text/template"
)

// Template injection via PostFormValue
func Handler00087(w http.ResponseWriter, r *http.Request) {
	body := r.PostFormValue("body")
	t, _ := template.New("t").Parse(body)
	t.Execute(w, nil)
}
