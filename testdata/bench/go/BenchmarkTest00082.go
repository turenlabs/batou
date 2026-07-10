package bench

import (
	"fmt"
	"net/http"
	"text/template"
)

// Template injection via fmt.Sprintf template
func Handler00082(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmplStr := fmt.Sprintf("Hello {{.Name}}! %s", name)
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, map[string]string{"Name": "World"})
}
