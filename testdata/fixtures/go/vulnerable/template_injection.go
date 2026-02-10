package vulnerable

import (
	"net/http"
	"text/template"
)

// VULN: Server-side template injection - user input used as template source.
// Should trigger detection for unsafe text/template usage with user-controlled input.

func HandleGreeting(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")

	tmplStr := "Hello, " + name + "! Welcome to our site."
	tmpl, err := template.New("greeting").Parse(tmplStr)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}
