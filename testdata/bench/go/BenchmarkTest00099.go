package bench

import (
	"net/http"
	"text/template"
)

// Hardcoded template, no user input in parse
func Handler00099(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("ignored")
	t, _ := template.New("t").Parse("Static page content")
	t.Execute(w, nil)
}
