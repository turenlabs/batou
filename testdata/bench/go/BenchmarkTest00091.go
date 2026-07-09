package bench

import (
	"net/http"
	"text/template"
)

// Fixed template, user data in context only
func Handler00091(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	t, _ := template.New("t").Parse("Hello, {{.Name}}!")
	t.Execute(w, map[string]string{"Name": name})
}
